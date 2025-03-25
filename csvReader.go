package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/boltdb/bolt"
)

func readCSVToMap() (map[string]string, error) {
	filename := "output.csv"
	// Open the CSV file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a CSV reader
	reader := csv.NewReader(file)

	// Initialize the map
	data := make(map[string]string)

	// Read the header row and skip it
	if _, err := reader.Read(); err != nil {
		return nil, err
	}

	// Read remaining rows and populate the map
	for {
		record, err := reader.Read()
		if err != nil {
			break // Exit loop at EOF or error
		}
		if len(record) < 2 {
			continue // Skip rows with insufficient columns
		}
		data[record[0]] = record[1] // Map first column as key, third as value
	}

	return data, nil
}
func readCSVTo2LayerMap() (map[string]map[string]string, error) {
	filename := "output.csv"
	// Open the CSV file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a CSV reader
	reader := csv.NewReader(file)

	// Initialize the main map
	result := make(map[string]map[string]string)

	// Read and skip the header row
	if _, err := reader.Read(); err != nil {
		fmt.Println("Error reading header:", err)
		return nil, err
	}

	// Process each row in the CSV
	for {
		record, err := reader.Read()
		if err != nil {
			break // Exit loop on EOF or error
		}
		if len(record) < 4 {
			continue // Skip rows with fewer than 4 columns
		}

		// Extract the columns
		col1 := record[0]
		col3 := record[2]
		col4 := record[3]

		// Check if the 3rd column value already exists in the outer map
		if _, exists := result[col3]; !exists {
			// If not, create a new inner map for this 3rd column key
			result[col3] = make(map[string]string)
		}

		// Insert the 1st and 4th column values into the inner map
		result[col3][col1] = col4
	}

	return result, nil
}

func updateAttrInJson(jsonString string, key string, value string) (string, error) {
	print := false
	var jsonObject map[string]interface{}
	if err := json.Unmarshal([]byte(jsonString), &jsonObject); err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	// Modify the content of the JSON object
	if oldValue, ok := jsonObject[key]; ok {
		jsonObject[key] = value
		if print {
			fmt.Printf("Original %s %s\n", key, oldValue)
			fmt.Printf("New %s %s\n", key, value)
		}
	}
	// Convert JSON object back to string
	modifiedJSONString, err := json.Marshal(jsonObject)
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	if print {
		fmt.Println("Modified JSON string:", string(modifiedJSONString))
	}
	return string(modifiedJSONString), nil
}

func UpdateSeverity() error {
	db := InitDB()
	defer db.Close()
	bucketNameVul := "vulnerability"

	severity, err := readCSVToMap()
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	// Begin a read-write transaction
	err = db.Update(func(tx *bolt.Tx) error {
		// Retrieve the specified bucket (create it if it doesn't exist)
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketNameVul))
		if err != nil {
			return err
		}
		for key, value := range severity {
			fmt.Println(key, value)
			// Retrieve the value associated with the key
			val := bucket.Get([]byte(key))
			if val == nil {
				fmt.Printf("key '%s' not found in bucket '%s'\n", key, bucketNameVul)
				continue
			}
			// Convert the value to a string
			jsonString := string(val)
			// jsonString, err := readValue(db, bucketNameVul, key)
			// if err != nil {
			// 	fmt.Println("Error:", err)
			// 	continue
			// }

			newJsonString, err := updateAttrInJson(jsonString, "Severity", value)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			// Convert the value to bytes
			newValueBytes := []byte(newJsonString)
			// Put the new value into the bucket with the specified key
			err = bucket.Put([]byte(key), newValueBytes)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			// updateValue(db, bucketNameVul, key, newJsonString)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func UpdatePkgVersion() error {
	db := InitDB()
	defer db.Close()
	bucketNameVul := "vulnerability"

	data, err := readCSVTo2LayerMap()
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	// Begin a read-write transaction
	err = db.Update(func(tx *bolt.Tx) error {
		// Traverse all top-level buckets
		err = tx.ForEach(func(bucketName []byte, bucket *bolt.Bucket) error {
			if string(bucketName) == bucketNameVul {
				// skip "vulnerability"
				return nil
			}
			// traverse a bucket
			c := bucket.Cursor()
			for pkgName, v := c.First(); pkgName != nil; pkgName, v = c.Next() {
				if v == nil {
					// This is a nested bucket
					subBucket := bucket.Bucket(pkgName)
					if subBucket == nil {
						continue
					}
					// Check if the pkg exists
					if subMap, exists := data[string(pkgName)]; exists {
						c2 := subBucket.Cursor()
						for cve, v2 := c2.First(); cve != nil; cve, v2 = c2.Next() {
							if v2 != nil {
								// This is a key-value pair
								// Check if the cve exists
								if version, ok := subMap[string(cve)]; ok {
									fmt.Printf("%s, %s, %s\n", string(pkgName), string(cve), version)
									jsonString := string(v2)
									newJsonString, err := updateAttrInJson(jsonString, "FixedVersion", version)
									if err != nil {
										fmt.Println("Error:", err)
										continue
									}
									// Put the new value into the bucket with the specified key
									err = subBucket.Put(cve, []byte(newJsonString))
									if err != nil {
										fmt.Println("Error:", err)
										continue
									}
								}
							}
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
