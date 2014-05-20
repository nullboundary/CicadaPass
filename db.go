package main

import (
	"github.com/couchbaselabs/go-couchbase"
	r "github.com/dancannon/gorethink"
	"labix.org/v2/mgo"
	"log"
	"time"
)

func connect(s Storer) {
	s.Conn()

}

func add(s Storer) {
	//s.Add(Data interface{})

}

func NewMongo() *Mongo {
	return &Mongo{}
}

func NewCouchBase() *CouchB {
	return &CouchB{}
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
	FindByID(id string, data interface{})
}

type DBConner interface {
	Conn()
}

//////////////////////////////////////////////////////////////////////////
//
// MongoDB
//
//
//////////////////////////////////////////////////////////////////////////
type Mongo struct {
	url         string
	port        string
	dbName      string
	collectName string
	session     *mgo.Session
	collection  *mgo.Collection
}

func (m *Mongo) Conn() {

	sess, err := mgo.Dial(m.url + ":" + m.port)
	if err != nil {
		log.Fatal("MongoDB-connectDB:", err)
	}

	sess.SetMode(mgo.Monotonic, true)

	m.session = sess
}

func (m *Mongo) Add(tableName string, data interface{}) {

	ses := m.session.Clone() //clone or copy? the session for every request
	defer ses.Close()        //close the session when function is complete.

	//how to change db or collections between calls to add?
	//Or set all ahead of time in envVar? create separte instance of storer ?
	col := ses.DB(m.dbName).C(m.collectName)
	m.collection = col

	log.Println("db-add")
	//newId := bson.NewObjectId()
	//jsonData.DeviceId = newId
	//err := col.Insert(&jsonData)
}

func (m *Mongo) FindAll(data interface{}, result interface{}) {
	ses := m.session.Clone()
	defer ses.Close()

	log.Println("db-FindAll")
	//return nil
}

func (m *Mongo) FindByID(id string, data interface{}) {
	ses := m.session.Clone()
	defer ses.Close()

	log.Println("db-FindById")

	//return nil
}

func (m *Mongo) UpdateByID(id string, data interface{}) {
	ses := m.session.Clone()
	defer ses.Close()

	log.Println("db-UpdateById")
}

func (m *Mongo) DelByID(id string) {
	ses := m.session.Clone()
	defer ses.Close()

	log.Println("db-DelById")
}

//////////////////////////////////////////////////////////////////////////
//
// CouchBase
//
//
//////////////////////////////////////////////////////////////////////////
type CouchB struct {
	userName   string
	pass       string
	url        string
	port       string
	poolName   string
	bucketName string
	client     *couchbase.Client
	bucket     *couchbase.Bucket
}

func (cb *CouchB) Conn() {

	con, err := couchbase.Connect("http://" + cb.userName + ":" + cb.pass + "@" + cb.url + ":" + cb.port)
	//con, err := couchbase.Connect("http://" + cb.url + ":" + cb.port)

	if err != nil {
		log.Fatalf("couch Base Error connecting:  %v", err)
	}

	pool, err := con.GetPool(cb.poolName)
	if err != nil {
		log.Printf("couch Base - Pool Error, %v", err)
	}

	bt, err := pool.GetBucket(cb.bucketName)

	if err != nil {
		log.Printf("couch Base - Bucket Error, %v", err)
	}

	cb.bucket = bt
	cb.client = &con

}

func (cb *CouchB) Add(tableName string, data interface{}) {

	//_, err := cb.bucket.Add("key", 10, &data)
	//if err != nil {
	//	log.Printf("couchbase Add-Error:%v", err)
	//}
	//log.Printf("data:%v", data)
	//cb.bucket.Set("someKey", []string{"an", "example", "list"})

	//log.Println("db-add")

}

func (cb *CouchB) FindAll(data interface{}, result interface{}) {

	log.Println("db-FindAll")
	//return nil
}

func (cb *CouchB) FindByID(id string, data interface{}) {

	log.Println("db-FindById")
	//return nil
}

func (cb *CouchB) UpdateByID(id string, data interface{}) {

	log.Println("db-UpdateById")
}

func (cb *CouchB) DelByID(id string) {

	log.Println("db-DelById")
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
func (rt *ReThink) FindByID(id string, data interface{}) {

	log.Printf("db-FindById:%s", id)
	row, err := r.Table(rt.tableName).
		Get(id). //Filter(r.Row.Field("uuid").Eq(id)).
		RunRow(rt.session)

	if err != nil {
		log.Printf("Error Finding by ID: %s", err)
	}

	//var response beacon
	err = row.Scan(&data)
	if err != nil {
		log.Printf(err.Error())
	}

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
