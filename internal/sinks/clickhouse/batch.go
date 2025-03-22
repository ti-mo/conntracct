package clickhouse

import (
	"context"
	"fmt"
	"time"
	log "github.com/sirupsen/logrus"

)

type batch []*event

func (s *ClickhouseSink) newBatch() {
	s.batch = make(batch, 0, s.config.BatchSize)
	s.stats.SetBatchLength(0)
	log.WithField("sink", s.config.Name).Debugf("batchsize '%d'", s.config.BatchSize)
}

func (s *ClickhouseSink) addBatchEvent(e *event) {
	s.batchMu.Lock()
	s.batch = append(s.batch, e)

	batchLen := len(s.batch)
	s.stats.SetBatchLength(batchLen)

	if batchLen > int(s.config.BatchSize) {
		s.flushBatch()
	}

	s.batchMu.Unlock()
}

func (s *ClickhouseSink) flushBatch() {
	if len(s.batch) == 0 {
		return
	}

	select {
	case s.sendChan <- s.batch:
		s.stats.IncrBatchesQueued()
		s.stats.SetBatchQueueLength(len(s.sendChan))
	default:
		s.stats.IncrBatchDropped()
	}

	s.newBatch()
}

func (s *ClickhouseSink) sendBatch(b batch) {
	ctx := context.Background()
	tableName := fmt.Sprintf("%s_flows", s.config.Database)
	batch, err := s.conn.PrepareBatch(ctx, fmt.Sprintf("INSERT INTO %s.%s", s.config.Database, tableName))
	if err != nil {
		log.WithField("sink", s.config.Name).Error("failed to prepare batch operation. Error: %v", err)
	}
	for _, e := range b {
		start := time.Unix(0, int64(e.Start))
		ts := time.Unix(0, int64(e.Timestamp))
		err := batch.Append(
			e.FlowID,
			e.Hostname,
			e.State,
			e.BytesOrig,
			e.BytesRet,
			e.BytesTotal,
			e.PacketsOrig,
			e.PacketsRet,
			e.PacketsTotal,
			e.Connmark,
			e.SrcAddr,
			e.SrcPort,
			e.DstAddr,
			e.DstPort,
			e.NetNS,
			e.ProtoName,
			start,
			ts,
		)
		if err != nil {
			log.WithField("sink", s.config.Name).Error("failed append event to batch operations. Error: %v", err)
		}
	}

	err = batch.Send()
	if err != nil {
		log.WithField("sink", s.config.Name).Error("failed execute batch operation. Error: %v", err)
	}
}
