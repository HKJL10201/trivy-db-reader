package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/boltdb/bolt"
)

var PATH = "C:\\Users\\hkjl1\\AppData\\Local\\trivy\\db\\trivy.db"

func initDB() *bolt.DB {
	db, err := bolt.Open(PATH, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func traverseBucket(file *os.File, bucket *bolt.Bucket, depth int) {
	// traverse a bucket
	c := bucket.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if v == nil {
			// This is a nested bucket
			// fmt.Printf("%s[%s]\n", getIndent(depth), k)
			fmt.Fprintf(file, "%s[%s]\n", getIndent(depth), k)
			nestedBucket := bucket.Bucket(k)
			if nestedBucket != nil {
				traverseBucket(file, nestedBucket, depth+1)
			}
		} else {
			// This is a key-value pair
			// fmt.Printf("%s%s: %s\n", getIndent(depth), k, v)
			fmt.Fprintf(file, "%s%s: %s\n", getIndent(depth), k, v)
		}
	}
}

func getIndent(depth int) string {
	return strings.Repeat("  ", depth)
}

func dumpDB() {
	// dump the DB file to a txt file
	// Open the BoltDB file in read-only mode
	db, err := bolt.Open(PATH, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create or open the output file
	outputFile, err := os.Create("trivy-db.txt")
	// outputFile, err := os.Create("fanal-db.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	err = db.View(func(tx *bolt.Tx) error {
		// Traverse all top-level buckets
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			// fmt.Printf("Bucket: %s\n", name)
			fmt.Fprintf(outputFile, "Bucket: %s\n", name)
			traverseBucket(outputFile, b, 1)
			return nil
		})
	})
	if err != nil {
		log.Fatal(err)
	}
}

func readValue(db *bolt.DB, bucketName string, key string) (string, error) {
	var value string

	err := db.View(func(tx *bolt.Tx) error {
		// Retrieve the specified bucket
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket '%s' not found", bucketName)
		}
		// Retrieve the value associated with the key
		val := bucket.Get([]byte(key))
		if val == nil {
			return fmt.Errorf("key '%s' not found in bucket '%s'", key, bucketName)
		}
		// Convert the value to a string
		value = string(val)
		return nil
	})
	if err != nil {
		return "", err
	}
	// fmt.Println("Value:", value)
	return value, nil
}

func readValueFromSubBucket(db *bolt.DB, bucketName string, subBucketName string, key string) (string, error) {
	var value string

	err := db.View(func(tx *bolt.Tx) error {
		// Retrieve the main bucket
		mainBucket := tx.Bucket([]byte(bucketName))
		if mainBucket == nil {
			return fmt.Errorf("main bucket '%s' not found", bucketName)
		}
		// Retrieve the sub-bucket
		subBucket := mainBucket.Bucket([]byte(subBucketName))
		if subBucket == nil {
			return fmt.Errorf("sub-bucket '%s' not found in '%s'", subBucketName, bucketName)
		}
		// Retrieve the value associated with the key
		val := subBucket.Get([]byte(key))
		if val == nil {
			return fmt.Errorf("key '%s' not found in sub-bucket '%s'", key, subBucketName)
		}
		// Convert the value to a string
		value = string(val)
		return nil
	})

	if err != nil {
		return "", err
	}
	// fmt.Println("Value:", value)
	return value, nil
}

func searchCVE(db *bolt.DB, bucketName string, subBucketName string) error {
	// search all CVEs by system (bucketName) and package (subBucketName)
	// var value string

	err := db.View(func(tx *bolt.Tx) error {
		// Retrieve the main bucket
		mainBucket := tx.Bucket([]byte(bucketName))
		if mainBucket == nil {
			return fmt.Errorf("main bucket '%s' not found", bucketName)
		}
		// Retrieve the sub-bucket
		subBucket := mainBucket.Bucket([]byte(subBucketName))
		if subBucket == nil {
			return fmt.Errorf("sub-bucket '%s' not found in '%s'", subBucketName, bucketName)
		}
		// Retrieve the value associated with the key
		c := subBucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			fmt.Printf("%s: %s\n", k, v)
			details, er := readValue(db, "vulnerability", string(k))
			if er != nil {
				return er
			}
			fmt.Printf("%s\n", details)
		}
		return nil
	})

	if err != nil {
		return err
	}
	return nil
}

func updateValue(db *bolt.DB, bucketName string, key string, value string) error {
	// Begin a read-write transaction
	err := db.Update(func(tx *bolt.Tx) error {
		// Retrieve the specified bucket (create it if it doesn't exist)
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		// Convert the value to bytes
		newValueBytes := []byte(value)
		// Put the new value into the bucket with the specified key
		err = bucket.Put([]byte(key), newValueBytes)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Printf("Failed to update value: %v\n", err)
		return err
	}
	return nil
}

func updateValueInSubBucket(db *bolt.DB, bucketName string, subBucketName string, key string, value string) error {
	// Begin a read-write transaction
	err := db.Update(func(tx *bolt.Tx) error {
		// Retrieve the main bucket
		mainBucket := tx.Bucket([]byte(bucketName))
		if mainBucket == nil {
			return fmt.Errorf("main bucket '%s' not found", bucketName)
		}
		// Retrieve the specified bucket (create it if it doesn't exist)
		bucket, err := mainBucket.CreateBucketIfNotExists([]byte(subBucketName))
		if err != nil {
			return err
		}
		// Convert the value to bytes
		newValueBytes := []byte(value)
		// Put the new value into the bucket with the specified key
		err = bucket.Put([]byte(key), newValueBytes)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Printf("Failed to update value: %v\n", err)
		return err
	}
	return nil
}

func updateJsonString(jsonString string) (string, error) {
	var jsonObject map[string]interface{}
	if err := json.Unmarshal([]byte(jsonString), &jsonObject); err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	// Modify the content of the JSON object
	if title, ok := jsonObject["Title"]; ok {
		jsonObject["Title"] = fmt.Sprintf("%s %s", ">>>Hacking here<<<", title)
		fmt.Println("Original Title:", title)
		fmt.Println("Modified Title:", jsonObject["Title"])
	}
	// Convert JSON object back to string
	modifiedJSONString, err := json.Marshal(jsonObject)
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	fmt.Println("Modified JSON string:", string(modifiedJSONString))
	return string(modifiedJSONString), nil
}

func deleteSubBucket(db *bolt.DB, bucketName string, subBucketName string) {
	// Start a read-write transaction
	err := db.Update(func(tx *bolt.Tx) error {
		// Get the parent bucket
		parentBucket := tx.Bucket([]byte(bucketName))
		// Check if the parent bucket exists
		if parentBucket == nil {
			return fmt.Errorf("main bucket '%s' not found", bucketName)
		}
		// Delete the sub-bucket
		if err := parentBucket.DeleteBucket([]byte(subBucketName)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

// Test cases /////////////////////////////////////////////////////////////////////////

func updateTest() {
	db := initDB()
	defer db.Close()
	// bucketNameVul := "vulnerability"
	// key := "CVE-1234-0007"
	bucketName := "alpine 3.9"
	subBucketName := "expat"
	keyCVE := "CVE-2018-20843"
	readValueFromSubBucket(db, bucketName, subBucketName, keyCVE)
	// jsonString, err := readValue(db,bucketNameVul,keyCVE)
	// if err != nil {
	//     fmt.Println("Error:", err)
	// }
	// newJsonString, err := updateJsonString(jsonString)
	// if err != nil {
	//     fmt.Println("Error:", err)
	// }
	// updateValue(db,bucketNameVul,keyCVE,newJsonString)
	// newKey := "CVE-0000-20843"
	// newVal := "{\"FixedVersion\":\"2.2.7-r0\"}"
	newVal := "{}"
	// newDetails := "{\"Title\":\"This is Title\"}"
	// updateValueInSubBucket(db,bucketName,subBucketName,newKey,newVal)
	updateValueInSubBucket(db, bucketName, subBucketName, keyCVE, newVal)
	// updateValue(db,bucketNameVul,newKey,newDetails)
	// readValueFromSubBucket(db,bucketName,subBucketName,newKey)
	// readValue(db,bucketNameVul,newKey)
}

func graph2ModifyingCVE() {
	db := initDB()
	defer db.Close()
	bucketNameVul := "vulnerability"
	// key := "CVE-1234-0007"
	bucketName := "alpine 3.9"
	subBucketName := "expat"
	keyCVE := "CVE-2018-20843"
	readValueFromSubBucket(db, bucketName, subBucketName, keyCVE)
	newKey := keyCVE
	newVal := "{\"FixedVersion\":\"NONE\"}"
	updateValueInSubBucket(db, bucketName, subBucketName, newKey, newVal)
	newDetails := "{\"Title\":\"NONE\"}"
	updateValue(db, bucketNameVul, newKey, newDetails)
	readValueFromSubBucket(db, bucketName, subBucketName, newKey)
	readValue(db, bucketNameVul, newKey)
}

func graph3DeletingLib() {
	db := initDB()
	defer db.Close()
	bucketName := "alpine 3.9"
	subBucketName := "expat"
	deleteSubBucket(db, bucketName, subBucketName)
}

func testSearch() {
	db := initDB()
	defer db.Close()
	bucketName := "alpine 3.9"
	subBucketName := "expat"
	searchCVE(db, bucketName, subBucketName)
}

func main() {
	dumpDB()

	// updateTest()
	// graph2ModifyingCVE()
	// graph3DeletingLib()
	// testSearch()
}
