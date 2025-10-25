package epicserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"reflect"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
)

const (
	cacheModeKey = "epicserver:cacheMode"
	cacheTTLKey  = "epicserver:cacheTTL"
)

type CacheMode int

const (
	CacheModeDefault CacheMode = iota
	CacheModeBypass
	CacheModeRefresh
)

func BypassQueryCache(db *gorm.DB) *gorm.DB {
	return db.Set(cacheModeKey, CacheModeBypass)
}

func RefreshQueryCache(db *gorm.DB) *gorm.DB {
	return db.Set(cacheModeKey, CacheModeRefresh)
}

func WithQueryCacheTTL(db *gorm.DB, ttl time.Duration) *gorm.DB {
	return db.Set(cacheTTLKey, ttl)
}

type queryCachePlugin struct {
	cache *queryCache
	debug bool
}

func newQueryCachePlugin(cache *queryCache, debug bool) *queryCachePlugin {
	return &queryCachePlugin{
		cache: cache,
		debug: debug,
	}
}

func (p *queryCachePlugin) Name() string {
	return "epicserver:query-cache"
}

func (p *queryCachePlugin) Initialize(db *gorm.DB) error {
	return db.Callback().Query().Replace("gorm:query", p.handleQuery())
}

func (p *queryCachePlugin) handleQuery() func(*gorm.DB) {
	return func(tx *gorm.DB) {
		if tx == nil || tx.Error != nil || tx.Statement == nil {
			return
		}

		callbacks.BuildQuerySQL(tx)
		if tx.Error != nil {
			return
		}

		ctx := extractCacheContext(tx.Statement)
		if p.cache != nil && ctx.mode == CacheModeRefresh && ctx.key != "" {
			p.cache.delete(ctx.key)
		}

		if ctx.enabled() && ctx.mode != CacheModeRefresh && p.tryLoad(tx, ctx.key) {
			return
		}

		if tx.DryRun || tx.Error != nil {
			return
		}

		rows, err := tx.Statement.ConnPool.QueryContext(tx.Statement.Context, tx.Statement.SQL.String(), tx.Statement.Vars...)
		if err != nil {
			tx.AddError(err)
			return
		}
		defer func() {
			tx.AddError(rows.Close())
		}()

		gorm.Scan(rows, tx, 0)

		if tx.Statement.Result != nil {
			tx.Statement.Result.RowsAffected = tx.RowsAffected
		}

		if tx.Error == nil && ctx.enabled() {
			p.persist(tx, ctx.key, ctx.ttl)
		}
	}
}

func (p *queryCachePlugin) tryLoad(tx *gorm.DB, key string) bool {
	if p.cache == nil || key == "" || tx.Statement == nil || tx.Statement.Dest == nil {
		return false
	}

	payload, ok := p.cache.get(key)
	if !ok {
		return false
	}

	if err := json.Unmarshal(payload, tx.Statement.Dest); err != nil {
		return false
	}

	tx.RowsAffected = estimateRowsAffected(tx.Statement.Dest)
	if p.debug {
		log.Printf("query cache hit: %s", tx.Statement.SQL.String())
	}
	return true
}

func (p *queryCachePlugin) persist(tx *gorm.DB, key string, ttl time.Duration) {
	if p.cache == nil || key == "" || tx.Statement == nil || tx.Statement.Dest == nil {
		return
	}

	payload, err := json.Marshal(tx.Statement.Dest)
	if err != nil {
		return
	}

	p.cache.set(key, payload, ttl)
}

type cacheContext struct {
	key  string
	ttl  time.Duration
	mode CacheMode
}

func (c cacheContext) enabled() bool {
	return c.key != "" && c.mode != CacheModeBypass
}

func extractCacheContext(stmt *gorm.Statement) cacheContext {
	ctx := cacheContext{mode: CacheModeDefault}
	if stmt == nil {
		return ctx
	}

	if v, ok := stmt.Settings.Load(cacheModeKey); ok {
		if mode, ok := v.(CacheMode); ok {
			ctx.mode = mode
		}
	}

	if v, ok := stmt.Settings.Load(cacheTTLKey); ok {
		if ttl, ok := v.(time.Duration); ok {
			ctx.ttl = ttl
		}
	}

	if stmt.SQL.Len() == 0 {
		return ctx
	}

	ctx.key = buildCacheKey(stmt)
	return ctx
}

func buildCacheKey(stmt *gorm.Statement) string {
	if stmt == nil || stmt.SQL.Len() == 0 {
		return ""
	}

	hasher := sha256.New()
	hasher.Write([]byte(stmt.SQL.String()))

	if len(stmt.Vars) > 0 {
		params, err := json.Marshal(stmt.Vars)
		if err != nil {
			return ""
		}
		hasher.Write(params)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func estimateRowsAffected(dest interface{}) int64 {
	v := reflect.ValueOf(dest)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return 0
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map:
		return int64(v.Len())
	case reflect.Struct:
		return 1
	default:
		return 0
	}
}
