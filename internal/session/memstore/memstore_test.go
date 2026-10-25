package memstore_test

import (
	"testing"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/session"
	"github.com/fintrace-project/fintrace-bff/internal/session/memstore"
	"github.com/fintrace-project/fintrace-bff/internal/session/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(now func() time.Time) session.Store { return memstore.New(now) })
}
