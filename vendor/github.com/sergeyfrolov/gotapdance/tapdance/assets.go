package tapdance

import (
	"crypto/x509"
	"encoding/binary"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
)

type assets struct {
	sync.RWMutex
	path string

	config pb.ClientConf

	roots *x509.CertPool

	filenameStationPubkey string
	filenameRoots         string
	filenameClientConf    string
}

// could reset this internally to refresh assets and avoid woes of singleton testing
var assetsInstance *assets
var assetsOnce sync.Once

// Assets is an access point to asset managing singleton.
// First access to singleton sets path. Assets(), if called
// before SetAssetsDir() sets path to "./assets/"
func Assets() *assets {
	_initAssets := func() { initAssets("./assets/") }
	assetsOnce.Do(_initAssets)
	return assetsInstance
}

// AssetsSetDir sets the directory to read assets from.
// Functionally equivalent to Assets() after initialization, unless dir changes.
func AssetsSetDir(dir string) *assets {
	_initAssets := func() { initAssets(dir) }
	if assetsInstance != nil {
		assetsInstance.Lock()
		if dir != assetsInstance.path {
			Logger().Warnf("Assets path changed %s->%s. (Re)initializing.\n",
				assetsInstance.path, dir)
			assetsInstance.path = dir
			assetsInstance.readConfigs()
			assetsInstance.Unlock()
			return assetsInstance
		}
	}
	assetsOnce.Do(_initAssets)
	return assetsInstance
}

func initAssets(path string) {
	var defaultDecoys = []*pb.TLSDecoySpec{
		pb.InitTLSDecoySpec("192.122.190.104", "tapdance1.freeaeskey.xyz"),
		pb.InitTLSDecoySpec("192.122.190.105", "tapdance2.freeaeskey.xyz"),
		pb.InitTLSDecoySpec("192.122.190.106", "tapdance3.freeaeskey.xyz"),
	}

	defaultKey := []byte{81, 88, 104, 190, 127, 69, 171, 111, 49, 10, 254, 212, 178, 41, 183,
		164, 121, 252, 159, 222, 85, 61, 234, 76, 205, 179, 105, 171, 24, 153, 231, 12}

	defualtKeyType := pb.KeyType_AES_GCM_128
	defaultPubKey := pb.PubKey{Key: defaultKey, Type: &defualtKeyType}
	defaultGeneration := uint32(0)
	defaultDecoyList := pb.DecoyList{TlsDecoys: defaultDecoys}
	defaultClientConf := pb.ClientConf{DecoyList: &defaultDecoyList,
		DefaultPubkey: &defaultPubKey,
		Generation:    &defaultGeneration}

	assetsInstance = &assets{
		path:                  path,
		config:                defaultClientConf,
		filenameRoots:         "roots",
		filenameClientConf:    "ClientConf",
		filenameStationPubkey: "station_pubkey",
	}
	assetsInstance.readConfigs()
}

func (a *assets) GetAssetsDir() string {
	a.RLock()
	defer a.RUnlock()
	return a.path
}

func (a *assets) readConfigs() {
	readRoots := func(filename string) error {
		rootCerts, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(rootCerts)
		if !ok {
			return errors.New("Failed to parse root certificates")
		}
		a.roots = roots
		return nil
	}

	readClientConf := func(filename string) error {
		buf, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		clientConf := pb.ClientConf{}
		err = proto.Unmarshal(buf, &clientConf)
		if err != nil {
			return err
		}
		a.config = clientConf
		return nil
	}

	readPubkey := func(filename string) error {
		staionPubkey, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		if len(staionPubkey) != 32 {
			return errors.New("Unexpected keyfile length! Expected: 32. Got: " +
				strconv.Itoa(len(staionPubkey)))
		}
		copy(a.config.DefaultPubkey.Key[:], staionPubkey[0:32])
		return nil
	}

	var err error
	Logger().Infoln("Assets: reading from folder " + a.path)

	rootsFilename := path.Join(a.path, a.filenameRoots)
	err = readRoots(rootsFilename)
	if err != nil {
		Logger().Warningln("Assets: failed to read root ca file: " + err.Error())
	} else {
		Logger().Infoln("X.509 root CAs successfully read from " + rootsFilename)
	}

	clientConfFilename := path.Join(a.path, a.filenameClientConf)
	err = readClientConf(clientConfFilename)
	if err != nil {
		Logger().Warningln("Assets: failed to read ClientConf file: " + err.Error())
	} else {
		Logger().Infoln("Client config successfully read from " + clientConfFilename)
	}

	pubkeyFilename := path.Join(a.path, a.filenameStationPubkey)
	err = readPubkey(pubkeyFilename)
	if err != nil {
		Logger().Debugln("Assets: failed to read pubkey file: " + err.Error())
	} else {
		Logger().Infoln("Pubkey successfully read from " + pubkeyFilename)
	}
}

// Picks random decoy, returns Server Name Indication and addr in format ipv4:port
func (a *assets) GetDecoyAddress() (sni string, addr string) {
	a.RLock()
	defer a.RUnlock()

	decoys := a.config.DecoyList.TlsDecoys
	if len(decoys) == 0 {
		return "", ""
	}
	decoyIndex := getRandInt(0, len(decoys)-1)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, decoys[decoyIndex].GetIpv4Addr())
	// TODO: what checks need to be done, and what's guaranteed?
	addr = ip.To4().String() + ":443"
	sni = decoys[decoyIndex].GetHostname()
	return
}

// Gets random DecoySpec.
func (a *assets) GetDecoy() pb.TLSDecoySpec {
	a.RLock()
	defer a.RUnlock()

	decoys := a.config.DecoyList.TlsDecoys
	chosenDecoy := pb.TLSDecoySpec{}
	if len(decoys) == 0 {
		return chosenDecoy
	}
	decoyIndex := getRandInt(0, len(decoys)-1)
	chosenDecoy = *decoys[decoyIndex]

	// TODO: stop enforcing values >= defaults.
	// Fix ackhole instead
	if chosenDecoy.GetTimeout() < timeoutMin {
		timeout := uint32(timeoutMax)
		chosenDecoy.Timeout = &timeout
	}
	if chosenDecoy.GetTcpwin() < sendLimitMin {
		tcpWin := uint32(sendLimitMax)
		chosenDecoy.Tcpwin = &tcpWin
	}
	return chosenDecoy
}

func (a *assets) GetRoots() *x509.CertPool {
	a.RLock()
	defer a.RUnlock()

	return a.roots
}

func (a *assets) GetPubkey() *[32]byte {
	a.RLock()
	defer a.RUnlock()

	var pKey [32]byte
	copy(pKey[:], a.config.DefaultPubkey.Key[:])
	return &pKey
}

func (a *assets) GetGeneration() uint32 {
	a.RLock()
	defer a.RUnlock()

	return a.config.GetGeneration()
}

// Set ClientConf generation and store config to disk
func (a *assets) SetGeneration(gen uint32) (err error) {
	a.Lock()
	defer a.Unlock()

	copyGen := gen
	a.config.Generation = &copyGen
	err = a.saveClientConf()
	return
}

// Set Public key and store config to disk
func (a *assets) SetPubkey(pubkey pb.PubKey) (err error) {
	a.Lock()
	defer a.Unlock()

	copyPubkey := pubkey
	a.config.DefaultPubkey = &copyPubkey
	err = a.saveClientConf()
	return
}

// Set ClientConf and store config to disk
func (a *assets) SetClientConf(conf *pb.ClientConf) (err error) {
	a.Lock()
	defer a.Unlock()

	a.config = *conf
	err = a.saveClientConf()
	return
}

// Not goroutine-safe, use at your own risk
func (a *assets) GetClientConfPtr() *pb.ClientConf {
	return &a.config
}

// Overwrite currently used decoys and store config to disk
func (a *assets) SetDecoys(decoys []*pb.TLSDecoySpec) (err error) {
	a.Lock()
	defer a.Unlock()

	a.config.DecoyList.TlsDecoys = decoys
	err = a.saveClientConf()
	return
}

// Checks if decoy is in currently used ClientConf decoys list
func (a *assets) IsDecoyInList(decoy pb.TLSDecoySpec) bool {
	ipv4str := decoy.GetIpv4AddrStr()
	hostname := decoy.GetHostname()
	for _, d := range a.config.GetDecoyList().GetTlsDecoys() {
		if strings.Compare(d.GetHostname(), hostname) == 0 &&
			strings.Compare(d.GetIpv4AddrStr(), ipv4str) == 0 {
			return true
		}
	}
	return false
}

func (a *assets) saveClientConf() error {
	buf, err := proto.Marshal(&a.config)
	if err != nil {
		return err
	}
	filename := path.Join(a.path, a.filenameClientConf)
	tmpFilename := path.Join(a.path, "."+a.filenameClientConf+"."+getRandString(5)+".tmp")
	err = ioutil.WriteFile(tmpFilename, buf[:], 0644)
	if err != nil {
		return err
	}

	return os.Rename(tmpFilename, filename)
}
