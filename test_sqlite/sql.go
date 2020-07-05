package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"reflect"

	_ "github.com/mattn/go-sqlite3"
)

func maybefail(err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	log.Printf(format, args...)
	os.Exit(1)
}

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	maybefail(err, "error opening test sqlite3 :memory: db, %v", err)
	driver := db.Driver()
	fmt.Printf("driver\nT %T\nv %v\nv# %#v\n", driver, driver, driver)
	t := reflect.TypeOf(driver)
	fmt.Printf("TypeOf(driver).Name() = %#v\n", t.Name())
	fmt.Printf("TypeOf(driver).String() = %#v\n", t.String())
	if t.Kind() == reflect.Ptr {
		fmt.Printf("Elem.Name %#v\n", t.Elem().Name())
	}
}
