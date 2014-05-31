package main

import (
	"archive/zip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

var tokenPrivateKey string

func main() {

	tokenPrivateKey = `y0yArOR5I\)rZT8Kj6NaaJs;{T:h0p1` //TODO: lets make a new key and put this somewhere safer!

	goji.Post("/pass", createPass)
	goji.Get("/pass/:version/passes/:passTypeIdentifier", getByPassTypeId)
	goji.Get("/pass/:version/passes/:passTypeIdentifier/:serialNumber", getLatestByPassTypeId)
	goji.Post("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber", registerDevicePass)
	goji.Get("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/", getPassSerialbyDevice)
	goji.Delete("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber", unregisterDevice)
	goji.Post("/pass/:version/log", logErrors)

	goji.NotFound(NotFound)

	goji.Use(addDb)

	goji.Serve()
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func generatePass(passTypeId string, serialNum string, res http.ResponseWriter, db Storer) {

	var dlPass pass

	if !db.FindByID(passTypeId, &dlPass) {
		http.Error(res, "pass type not found", 404)
		return
	}

	dlPass.KeyDoc.SerialNumber = serialNum

	//fmt.Sprintf("%d", dlPass.Updated.Unix())
	//generate auth token - Don’t change the authentication token in an update.
	dlPass.KeyDoc.AuthenticationToken = generateAuthToken(tokenPrivateKey, serialNum, passTypeId)
	//log.Printf("authtoken: ", dlPass.KeyDoc.AuthenticationToken)

	//TODO: save serial + other info to db.

	//make manifestdoc map for storing sha1 hashes
	dlPass.ManifestDoc = make(map[string]string)

	// Create a new zip archive.
	res.Header().Set("Content-Type", "application/vnd.apple.pkpass") //sets the extension to pkpass
	w := zip.NewWriter(res)
	defer w.Close()

	//add the pass.json file to the zip pass
	file := addToZipFile(w, "pass.json")
	enc := json.NewEncoder(file)
	enc.Encode(dlPass.KeyDoc)

	//compute sha1 hash for pass.json
	dlPass.ManifestDoc["pass.json"] = fmt.Sprintf("%x", hashSha1Json(dlPass.KeyDoc))

	//add all images to the pass zip
	for i := range dlPass.Images {

		fileExt, imageBytes := decodetoBytes(dlPass.Images[i].ImageData)
		fileName := dlPass.Images[i].ImageName + fileExt
		file = addToZipFile(w, fileName)
		_, err := file.Write(imageBytes)
		check(err)

		//compute sha1 hash for each image file, add to manifest doc
		dlPass.ManifestDoc[fileName] = fmt.Sprintf("%x", hashSha1Bytes(imageBytes))
	}

	//add the manifest.json file to the zip pass
	file = addToZipFile(w, "manifest.json")
	enc = json.NewEncoder(file)
	enc.Encode(dlPass.ManifestDoc)
	debugPrintJson(dlPass.ManifestDoc)

	//TODO: sign pass

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
//
//
//
//////////////////////////////////////////////////////////////////////////
func hashSha1Json(jsonData interface{}) []byte {

	//compute sha1 hash for json
	hash := sha1.New()
	enc := json.NewEncoder(hash) //json encode writes to the hash function
	enc.Encode(jsonData)
	return hash.Sum(nil)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func hashSha1Bytes(hashBytes []byte) []byte {

	//compute sha1 hash of bytes
	hash := sha1.New()
	n, err := hash.Write(hashBytes)
	if n != len(hashBytes) || err != nil {
		panic(err)
	}
	return hash.Sum(nil)

}

//////////////////////////////////////////////////////////////////////////
//
//	generate a hash fnv1a hash. Fast, unique, but insecure! use only for ids and such.
//  https://programmers.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed
//
//////////////////////////////////////////////////////////////////////////
func generateFnvHashId(hashSeeds ...string) uint32 {

	inputString := strings.Join(hashSeeds, "")

	var randomness int32
	binary.Read(rand.Reader, binary.LittleEndian, &randomness) //add a little randomness
	inputString = fmt.Sprintf("%s%x", inputString, randomness)

	h := fnv.New32a()
	h.Write([]byte(inputString))
	return h.Sum32()

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func generateAuthToken(key string, seeds ...string) string {

	tokenSeed := strings.Join(seeds, "|")
	hmac := calcHMAC(tokenSeed, key)
	return base64.URLEncoding.EncodeToString(hmac)

}

//////////////////////////////////////////////////////////////////////////
//
// verifyToken returns true if messageMAC is a valid HMAC tag for message.
//
//
//////////////////////////////////////////////////////////////////////////
func verifyToken(key string, authToken string, seeds ...string) bool {

	decodedMac, err := base64.URLEncoding.DecodeString(authToken)
	if err != nil {
		panic(err)
	}

	tokenSeed := strings.Join(seeds, "|")

	return verifyHMAC(tokenSeed, decodedMac, key)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func calcHMAC(message string, key string) []byte {

	mac := hmac.New(sha256.New, []byte(key))
	n, err := mac.Write([]byte(message))
	if n != len(message) || err != nil {
		panic(err)
	}
	return mac.Sum(nil)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func verifyHMAC(message string, macOfMessage []byte, key string) bool {

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(macOfMessage, expectedMAC)
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
	http.Error(w, "Umm... have you tried turning it off and on again?", 404) //TODO: add 404 error message
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

	file, _ := os.Open(fileName) //TODO: change to read in through form or json
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

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func debugPrintJson(Data interface{}) {

	printJSon := json.NewEncoder(os.Stdout)
	printJSon.Encode(Data)
}
