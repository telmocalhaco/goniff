package sniffer

import (
	"context"
	"errors"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
)

var rdb *redis.Client
var ctx = context.Background()
var internalcache *cache.Cache
var isredis bool

func CacheInit(isredisi bool) {
	isredis = isredisi
	if isredis {
		rdb = redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		})
	} else {
		internalcache = cache.New(5*time.Minute, 10*time.Minute)
	}
}

func GetPacket(address string) (map[string]string, error) {
	if isredis {
		return rdb.HGetAll(ctx, address).Result()
	} else {
		aux, found := internalcache.Get(address)
		if found {
			return aux.(map[string]string), nil
		} else {
			return nil, errors.New("not found")
		}
	}
}

func SetPacket(packet GoniffPacket) {
	if isredis {
		rdb.HSet(ctx, packet.ip, "country", packet.country)
		rdb.HSet(ctx, packet.ip, "ptr", packet.ptr)
		rdb.HSet(ctx, packet.ip, "ASN", packet.ASN)
		rdb.HSet(ctx, packet.ip, "ORG", packet.ORG)
	} else {
		internalcache.Set(packet.ip, map[string]string{
			"country": packet.country,
			"ptr":     packet.ptr,
			"ASN":     packet.ASN,
			"ORG":     packet.ORG,
		}, cache.DefaultExpiration)
	}
}
