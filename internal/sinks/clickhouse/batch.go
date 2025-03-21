package clickhouse

import (
	"context"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

type batch []*bpf.Event

func (s *ClickhouseSink) newBatch() {
	s.batch = make(batch, 0, s.config.BatchSize)
	s.stats.SetBatchLength(0)
}

func (s *ClickhouseSink) addBatchEvent(e *bpf.Event) {
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
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO s.config.Database")
	if err != nil {
		return
	}
	for _, e := range b {
		err := batch.Append(
			e.FlowID,
			e.BytesOrig,
			e.BytesRet,
			0,
			e.PacketsOrig,
			e.PacketsRet,
			0,
			e.Connmark,
			e.SrcAddr,
			e.SrcPort,
			e.DstAddr,
			e.DstPort,
			e.NetNS,
			e.Start,
			e.Timestamp,
		)
		if err != nil {
			return
		}
	}
}
