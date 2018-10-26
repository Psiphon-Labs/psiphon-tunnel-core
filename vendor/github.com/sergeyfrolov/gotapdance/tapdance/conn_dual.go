package tapdance

import (
	"context"
	"errors"
	"net"
	"strconv"
)

// DualConn is composed of 2 separate TapdanceFlowConn.
// Allows to achieve substantially higher upload speed
// and slightly higher download speed.
type DualConn struct {
	net.Conn
	writerConn *TapdanceFlowConn
	readerConn *TapdanceFlowConn

	sessionId uint64 // constant for logging
}

// returns TapDance connection that utilizes 2 flows underneath: reader and writer
func dialSplitFlow(ctx context.Context, customDialer func(context.Context, string, string) (net.Conn, error),
	covert string) (net.Conn, error) {
	dualConn := DualConn{sessionId: sessionsTotal.GetAndInc()}
	stationPubkey := Assets().GetPubkey()

	rawRConn := makeTdRaw(tagHttpGetIncomplete, stationPubkey[:])
	if customDialer != nil {
		rawRConn.TcpDialer = customDialer
	}
	rawRConn.sessionId = dualConn.sessionId
	rawRConn.strIdSuffix = "R"

	var err error
	dualConn.readerConn, err = makeTdFlow(flowReadOnly, rawRConn, covert)
	if err != nil {
		return nil, err
	}
	err = dualConn.readerConn.DialContext(ctx)
	if err != nil {
		return nil, err
	}

	// net.Conn functions that are not explicitly declared will be performed by readerConn
	dualConn.Conn = dualConn.readerConn

	// TODO: traffic fingerprinting issue
	// TODO: fundamental issue of observable dependency between 2 flows
	err = dualConn.readerConn.yieldUpload()
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		return nil, err
	}

	rawWConn := makeTdRaw(tagHttpPostIncomplete,
		stationPubkey[:])
	if customDialer != nil {
		rawRConn.TcpDialer = customDialer
	}
	rawWConn.sessionId = dualConn.sessionId
	rawWConn.strIdSuffix = "W"
	rawWConn.decoySpec = rawRConn.decoySpec
	rawWConn.pinDecoySpec = true

	dualConn.writerConn, err = makeTdFlow(flowUpload, rawWConn, covert)
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		return nil, err
	}
	err = dualConn.writerConn.DialContext(ctx)
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		return nil, err
	}

	err = dualConn.writerConn.acquireUpload()
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		dualConn.writerConn.closeWithErrorOnce(err)
		return nil, err
	}
	/* // TODO: yield confirmation
	writerConn.yieldConfirmed = make(chan struct{})
	go func() {
		time.Sleep(time.Duration(getRandInt(1234, 5432)) * time.Millisecond)
		Logger().Infoln(dualConn.idStr() + " faking yield confirmation!")
		writerConn.yieldConfirmed <- struct{}{}
	}()
	err = writerConn.WaitForYieldConfirmation()
	if err != nil {
		dualConn.readerConn.Close()
		writerConn.Close()
		return nil, err
	}
	*/
	go func() {
		select {
		case <-dualConn.readerConn.closed:
			dualConn.writerConn.closeWithErrorOnce(errors.New("in paired readerConn: " +
				dualConn.readerConn.closeErr.Error()))
		case <-dualConn.writerConn.closed:
			dualConn.readerConn.closeWithErrorOnce(errors.New("in paired writerConn: " +
				dualConn.writerConn.closeErr.Error()))
		}
	}()
	return &dualConn, nil
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (tdConn *DualConn) Write(b []byte) (int, error) {
	return tdConn.writerConn.Write(b)
}

func (tdConn *DualConn) idStr() string {
	return "[Session " + strconv.FormatUint(tdConn.sessionId, 10) + "]"
}
