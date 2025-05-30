package http

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

type Place struct {
	PlaceKey             *int    `json:"place_key,omitempty"`
	PlaceName            *string `json:"place_name,omitempty"`
	PlaceShortName       *string `json:"place_short_name,omitempty"`
	PlaceDivisionUnitKey *int    `json:"place_division_unit_key,omitempty"`
	ParentPlaceKey       *int    `json:"parent_place_key,omitempty"`
	LeaderPlaceKey       *int    `json:"leader_place_key,omitempty"`
	CountryPlaceKey      *int    `json:"country_place_key,omitempty"`
	CountryName          *string `json:"country_name,omitempty"`
	CountryShortName     *string `json:"country_short_name,omitempty"`
	ProvincePlaceKey     *int    `json:"province_place_key,omitempty"`
	ProvinceName         *string `json:"province_name,omitempty"`
	ProvinceShortName    *string `json:"province_short_name,omitempty"`
	MunicipalName        *string `json:"municipal_name,omitempty"`
	MunicipalShortName   *string `json:"municipal_short_name,omitempty"`
}

func TestParsePath(t *testing.T) {
	paths, id := ParsePath("/", true, true)
	t.Log(paths, id)

	paths, id = ParsePath("/acct/Auth/ss", true, true)
	t.Log(paths, id)
}

func TestRoutePath(t *testing.T) {
	r := chi.NewRouter()
	r.HandleFunc("/route/handle/",
		func(w http.ResponseWriter, r *http.Request) {
			paths, id := ParseRouteVars(r, false)
			_ = paths
			_ = id
			w.Write([]byte("Hello, forward slashed!"))
		})
	r.HandleFunc("/route/handle/key",
		func(w http.ResponseWriter, r *http.Request) {
			paths, id := ParseRouteVars(r, false)
			_ = paths
			_ = id
			w.Write([]byte("Hello, expected key!"))
		})
	r.HandleFunc("/route/{handlex}",
		func(w http.ResponseWriter, r *http.Request) {
			paths, id := ParseRouteVars(r, false)
			_ = paths
			_ = id
			w.Write([]byte("Hello, route with no forward slash"))
		})

	obj := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths, id := ParseRouteVars(r, false)
			_ = paths
			_ = id
			w.Write([]byte("Hello, route with no forward slash"))
		})
	}
	r.Handle("/route/german/*", obj())

	go func() {
		httpServer := &http.Server{
			Addr:    ":8080",
			Handler: r,
		}
		httpServer.ListenAndServe()
	}()

	data, err := ExecuteApi[string](
		"GET",
		"http://localhost:8080/route/german/handlex", nil,
		Headers(map[string]string{
			"Content-Type": "plain/text",
		}))
	if err != nil {
		t.Log(err)
		t.Fail()
		return
	}
	t.Log(data)
}

func TestReadAPI(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(30)
	for i := range 30 {
		go func() {
			defer wg.Done()
			rl := ReadApi[[]Place](
				"http://localhost:8010/place/municipal/",
				Headers(map[string]string{
					"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjAsIm5iZiI6MTc0ODIzNjgyOCwiaWF0IjowLCJ1c3IiOiJ6YWxkeS5iYWd1aW5vbiJ9.k2FjJmdE95PuQbDEQ17kw0Jh-L1OlPSPJq9pxCCcrQo",
				}))
			if !rl.OK() {
				fmt.Println("PLACE:" + rl.MessagesToString())
				t.Fail()
				return
			}
			t.Logf("[%d]:%+v", i, rl.Data[0])
		}()
	}
	wg.Wait()
}

func BenchmarkReadAPI(b *testing.B) {
	rl := ReadApi[[]Place](
		"http://localhost:8010/place/municipal/",
		Headers(map[string]string{
			"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjAsIm5iZiI6MTc0ODIzNjgyOCwiaWF0IjowLCJ1c3IiOiJ6YWxkeS5iYWd1aW5vbiJ9.k2FjJmdE95PuQbDEQ17kw0Jh-L1OlPSPJq9pxCCcrQo",
		}))
	if !rl.OK() {
		fmt.Println("PLACE:" + rl.MessagesToString())
		b.Fail()
	}
}
