package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

func main() {

	goji.Post("/pass", createPass)
	goji.Get("/pass/:id", getPassById)

	goji.NotFound(NotFound)

	goji.Use(addDb)

	goji.Serve()
}

//////////////////////////////////////////////////////////////////////////
//
//	createPass Handler
//
//
//////////////////////////////////////////////////////////////////////////
func createPass(c web.C, res http.ResponseWriter, req *http.Request) {

	db, err := getDbType(c)
	if err != nil {
		log.Println(err.Error())
	}

	var newPass pass

	readJson(req, &newPass.KeyDoc) //TODO: create schema to validate data is correct

	uri, err := encodetoDataUri("icon.png", ".png")
	check(err)
	var image passImage
	image.ImageData = uri
	image.ImageName = "icon"
	newPass.Images = append(newPass.Images, image)

	//Unique Id for the db and the pass file name
	idHash := generateFnvHashId(newPass.KeyDoc.Description, time.Now().String())  //generate a hash using pass description + time
	companyName := strings.Replace(newPass.KeyDoc.OrganizationName, " ", "-", -1) //remove spaces from organization name
	newPass.Id = fmt.Sprintf("%s-%d", companyName, idHash)

	db.Add("pass", &newPass)

}

//////////////////////////////////////////////////////////////////////////
//
//	createPass Handler
//
//
//////////////////////////////////////////////////////////////////////////
func getPassById(c web.C, res http.ResponseWriter, req *http.Request) {

	log.Println("getPassById")

	db, err := getDbType(c)
	if err != nil {
		log.Println(err.Error())
	}

	var dlPass pass

	db.FindByID(c.URLParams["id"], &dlPass)

	//generate a unique serial number for this pass being downloaded
	idHash := generateFnvHashId(req.UserAgent(), time.Now().String())
	dlPass.KeyDoc.SerialNumber = fmt.Sprintf("%d", idHash)

	// Create a new zip archive.
	res.Header().Set("Content-Type", "application/vnd.apple.pkpass")
	w := zip.NewWriter(res)
	defer w.Close()

	//add the pass.json file to the zip pass
	file := addToZipFile(w, "pass.json")
	enc := json.NewEncoder(file)
	enc.Encode(dlPass.KeyDoc)

	//add all images to the pass zip
	for i := range dlPass.Images {

		fileExt, imageBytes := decodetoBytes(dlPass.Images[i].ImageData)
		file = addToZipFile(w, dlPass.Images[i].ImageName+fileExt)
		_, err = file.Write(imageBytes)
		check(err)
	}

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func check(e error) {
	if e != nil {
		panic(e)
	}
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func addToZipFile(zWrite *zip.Writer, fileName string) io.Writer {

	var header zip.FileHeader
	header.Name = fileName
	header.SetModTime(time.Now().UTC())
	file, err := zWrite.CreateHeader(&header)
	check(err)

	return file

}

//////////////////////////////////////////////////////////////////////////
//
//	generate a hash fnv1a hash. Fast, unique, but insecure! use only for ids and such.
//
//
//////////////////////////////////////////////////////////////////////////
func generateFnvHashId(hashSeeds ...string) uint32 {

	inputString := strings.Join(hashSeeds, "")

	var randomness int32
	binary.Read(rand.Reader, binary.LittleEndian, &randomness) //add a little randomness
	inputString = fmt.Sprintf("%s%d", inputString, randomness)

	h := fnv.New32a()
	h.Write([]byte(inputString))
	idHash := h.Sum32()

	return idHash
}

//////////////////////////////////////////////////////////////////////////
//
//	addDb Middleware
//
//
//////////////////////////////////////////////////////////////////////////
func addDb(c *web.C, h http.Handler) http.Handler {
	handler := func(w http.ResponseWriter, r *http.Request) {

		if c.Env == nil {
			c.Env = make(map[string]interface{})
		}

		if _, ok := c.Env["db"]; !ok { //test is the db is already added

			rt := NewReThink()
			rt.url = "127.0.0.1"
			rt.port = "28015"
			rt.dbName = "test"
			rt.tableName = "pass"

			s := Storer(rt) //abstract cb to a Storer
			s.Conn()

			c.Env["db"] = s //add db
		}

		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(handler)
}

//////////////////////////////////////////////////////////////////////////
//
// NotFound is a 404 handler.
//
//
//////////////////////////////////////////////////////////////////////////
func NotFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Umm... have you tried turning it off and on again?", 404)
}

//////////////////////////////////////////////////////////////////////////
//
//	getDbType
//
//
//////////////////////////////////////////////////////////////////////////
func getDbType(c web.C) (Storer, error) {

	if v, ok := c.Env["db"]; ok {

		if db, ok := v.(Storer); ok {

			return db, nil //all good

		} else {
			err := fmt.Errorf("value could not convert to type Storer")
			return nil, err
		}

	} else {
		err := fmt.Errorf("value for key db, not found")
		return nil, err
	}

}

//////////////////////////////////////////////////////////////////////////
//
// encodetoDataUri
//
//
//////////////////////////////////////////////////////////////////////////
func encodetoDataUri(fileName string, allowTypes ...string) (string, error) {

	file, _ := os.Open(fileName)
	defer file.Close()

	fileInfo, _ := file.Stat() // FileInfo interface
	size := fileInfo.Size()    // file size

	data := make([]byte, size)

	contentType := path.Ext(fileName)

	typeFound := false
	for _, fileType := range allowTypes { //match the type with the allowed types
		if contentType == fileType {
			typeFound = true
			break
		}
	}

	if !typeFound {
		err := fmt.Errorf("file type: %s not allowed", contentType)
		return "", err
	}

	file.Read(data)

	return fmt.Sprintf("data:%s;base64,%s", contentType, base64.StdEncoding.EncodeToString(data)), nil
}

//////////////////////////////////////////////////////////////////////////
//
// decodetoBytes
//
//
//////////////////////////////////////////////////////////////////////////
func decodetoBytes(str string) (string, []byte) {

	dataStr := strings.SplitN(str, ",", 2) //seperate data:png;base64, from the DataURI

	dataType := strings.Trim(dataStr[0], "data:;base64") //extract only the file type

	data, err := base64.StdEncoding.DecodeString(dataStr[1]) // [] byte
	check(err)

	return dataType, data

}

//////////////////////////////////////////////////////////////////////////
//
// Encodes data into a 'data:' URI specified at
// https://developer.mozilla.org/en/data_URIs.
//
//////////////////////////////////////////////////////////////////////////
func dataUrl(data []byte, contentType string) string {
	return fmt.Sprintf("data:%s;base64,%s",
		contentType, base64.StdEncoding.EncodeToString(data))
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func readJson(req *http.Request, jsonData interface{}) {

	if err := json.NewDecoder(req.Body).Decode(&jsonData); err != nil {
		fmt.Printf("jsonRead Error:%v", err)
		//return &serverError{err, "400 Bad Request", http.StatusBadRequest} //TODO: return error encoded as json?
	}

	//return nil
}
