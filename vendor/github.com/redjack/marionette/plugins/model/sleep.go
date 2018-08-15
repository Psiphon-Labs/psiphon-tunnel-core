package model

import (
	"context"
	"errors"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redjack/marionette"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("model", "sleep", Sleep)
}

// SleepFactor is the multiplier the sleep value is multipled by.
// By default the sleep is not adjusted.
var SleepFactor = 1.0

func Sleep(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	t0 := time.Now()

	logger := marionette.Logger.With(
		zap.String("plugin", "model.sleep"),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 1 {
		return errors.New("not enough arguments")
	}
	distStr, ok := args[0].(string)
	if !ok {
		return errors.New("invalid argument type")
	}

	dist, err := ParseSleepDistribution(distStr)
	if err != nil {
		return err
	}

	keys := make([]float64, 0, len(dist))
	for k := range dist {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	sum, coin := float64(0), rand.Float64()
	var k float64
	for _, k = range keys {
		sum += dist[k]
		if sum >= coin {
			break
		}
	}

	duration := time.Duration(k * float64(time.Second) * SleepFactor)
	time.Sleep(duration)

	logger.Debug("sleep complete", zap.Duration("duration", duration), zap.Duration("t", time.Since(t0)))

	return nil
}

func ParseSleepDistribution(s string) (map[float64]float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "{")
	s = strings.TrimRight(s, "}")
	s = strings.Replace(s, " ", "", -1)
	s = strings.Replace(s, "\n", "", -1)
	s = strings.Replace(s, "\t", "", -1)
	s = strings.Replace(s, "\r", "", -1)

	dist := make(map[float64]float64)
	for _, item := range strings.Split(s, ",") {
		a := strings.Split(item, ":")
		a[0] = strings.Trim(a[0], "'")

		val, err := strconv.ParseFloat(a[0], 64)
		if err != nil {
			return nil, err
		}

		prob, err := strconv.ParseFloat(a[1], 64)
		if err != nil {
			return nil, err
		}

		if val > 0 {
			dist[val] = prob
		}
	}

	return dist, nil
}
