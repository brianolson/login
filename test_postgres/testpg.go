package main

import (
	"database/sql"
	"flag"
	"fmt"
	"reflect"

	_ "github.com/lib/pq"

	tu "bolson.org/~/src/login/login/sql/testutil"
)

var maybefail = tu.Maybefail

func main() {
	var pgConnectString string
	flag.StringVar(&pgConnectString, "postgres", "", "connection string for postgres")
	flag.Parse()
	db, err := sql.Open("postgres", pgConnectString)
	maybefail(err, "error opening postgres db, %v", err)
	driver := db.Driver()
	fmt.Printf("driver\nT %T\nv %v\nv# %#v\n", driver, driver, driver)
	t := reflect.TypeOf(driver)
	fmt.Printf("TypeOf(driver).Name() = %#v\n", t.Name())
	fmt.Printf("TypeOf(driver).String() = %#v\n", t.String())
	fmt.Printf("TypeOf(driver).PkgPath() = %#v\n", t.PkgPath())
	if t.Kind() == reflect.Ptr {
		fmt.Printf("Elem.Name %#v\n", t.Elem().Name())
		fmt.Printf("TypeOf(*driver).PkgPath() = %#v\n", t.Elem().PkgPath())
		fmt.Printf("TypeOf(*driver).String() = %#v\n", t.Elem().String())
	}
}
