package main

import (
	r "github.com/dancannon/gorethink"
	"log"
	"time"
)

func connect(s Storer) {
	s.Conn()

}

func add(s Storer) {
	//s.Add(Data interface{})

}

func NewReThink() *ReThink {
	return &ReThink{}
}

//////////////////////////////////////////////////////////////////////////
//
// Interfaces
//
//
//////////////////////////////////////////////////////////////////////////
type Storer interface {
	DBModder
	DBFinder
	DBConner
}

type DBModder interface {
	Add(tableName string, data interface{})
	UpdateByID(id string, data interface{})
	DelByID(id string)
}

type DBFinder interface {
	FindAll(data interface{}, result interface{})
	FindByID(id string, data interface{}) bool
}

type DBConner interface {
	Conn()
}

//////////////////////////////////////////////////////////////////////////
//
// ReThinkDB
//
//
//////////////////////////////////////////////////////////////////////////
type ReThink struct {
	url       string
	port      string
	dbName    string
	tableName string //TODO, probably need a few of these []?
	session   *r.Session
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (rt *ReThink) Conn() {

	sess, err := r.Connect(r.ConnectOpts{
		Address:     rt.url + ":" + rt.port,
		Database:    rt.dbName,
		MaxIdle:     10,
		IdleTimeout: time.Second * 10,
	})
	if err != nil {
		log.Fatal("Rethink-connectDB:", err)
	}

	// Setup database
	//r.Db("test").TableDrop("table").Run(sess)
	/*
		response, err := r.Db(rt.dbName).TableCreate(rt.tableName).RunWrite(sess)
		if err != nil {
			log.Fatalf("Error creating table: %s", err)
		}

		fmt.Printf("%d table created", response.Created)
	*/
	rt.session = sess
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (rt *ReThink) Add(tableName string, data interface{}) {

	log.Printf("data:%v", data)
	response, err := r.Table(tableName).Insert(data).RunWrite(rt.session)
	if err != nil {
		log.Printf("Error inserting data: %s", err)
		return
	}

	log.Printf("db-add:%v", response)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (rt *ReThink) FindAll(data interface{}, result interface{}) {

	//result := []beacon{}
	//result := []data{}
	/*
		s := reflect.ValueOf(result)
		if s.Kind() != reflect.Slice {
			panic("InterfaceSlice() given a non-slice type")
		}

		rows, err := r.Table(rt.tableName).Run(rt.session)
		if err != nil {
			log.Printf("Error Finding All data: %s", err)
		}

		//rows.ScanAll(&data)

		for rows.Next() {
			//var b beacon
			err := rows.Scan(&data)
			if err != nil {
				log.Println(err)
			}

			//result[len(result)-1] = data
			s := append(s, data)
		}

		log.Printf("db-result:%v", data)

		log.Println("db-FindAll")
	*/
	//return result

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (rt *ReThink) FindByID(id string, data interface{}) bool {

	log.Printf("db-FindById:%s", id)
	row, err := r.Table(rt.tableName).
		Get(id). //Filter(r.Row.Field("uuid").Eq(id)).
		RunRow(rt.session)

	if err != nil {
		log.Printf("Error Finding by ID: %s", err)
	}

	if row.IsNil() {
		return false
	}

	//var response beacon
	err = row.Scan(&data)
	if err != nil {
		log.Printf(err.Error())
	}

	return true

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (rt *ReThink) UpdateByID(id string, data interface{}) {

	response, err := r.Table(rt.tableName).
		Get(id). //Filter(r.Row.Field("uuid").Eq(id)).
		Update(data).
		RunWrite(rt.session)

	if err != nil {
		log.Printf("Error updating data: %s", err)
		return
	}

	log.Printf("db-UpdateById:%v", response)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (rt *ReThink) DelByID(id string) {

	// Delete the item
	response, err := r.Table(rt.tableName).Get(id).Delete().RunWrite(rt.session)
	if err != nil {
		log.Printf("Error Deleting by ID: %s", err)
		return
	}

	log.Printf("db-DelById:%v", response)
}
