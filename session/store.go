package session

import (
	"github.com/alexedwards/scs/gormstore"
	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"gorm.io/gorm"
)

func NewMemoryStore() scs.Store {
	return memstore.New()
}

func NewDatabaseStore(db *gorm.DB) (scs.Store, error) {
	store, err := gormstore.NewWithCleanupInterval(db, 0)
	return store, err
}
