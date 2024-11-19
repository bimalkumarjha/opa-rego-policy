package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"opa-poc/helper"
)

func main() {

	///var memStart, memEnd runtime.MemStats
	//runtime.ReadMemStats(&memStart)
	// Load rules only once
	helper.LoadRules("policies/rule.json")

	// Initialize Rego instances
	//helper.InitDbUserRegoInstance("policies/dbuser_policy.rego")
	helper.InitDbUserRegoInstance("policies/dbusercommonPolicy.rego")

	helper.InitDatabaseRegoInstance("policies/database_policy.rego")
	//helper.InitOsuserRegoInstance("policies/osuser_policy.rego")
	// End memory tracking and calculate memory usage
	//runtime.ReadMemStats(&memEnd)
	//memoryUsedMB := float64(memEnd.Alloc-memStart.Alloc) / (1024 * 1024)
	//fmt.Println()
	//fmt.Printf("Memory Used: %.2f MB\n", memoryUsedMB)

	inputs := loadInputs("input1.json")

	startTime := time.Now()
	totalRecords := len(inputs)

	// Counter for rule executions
	ruleExecutionCount := 0

	// Execute rule evaluation for each input
	for _, input := range inputs {
		severity, matchedFeatures := helper.RuleExecution(input)
		fmt.Printf("Input: %v\nSeverity: %s\nMatched Features: %v\n\n", input, severity, matchedFeatures)
		ruleExecutionCount++
	}

	elapsedTime := time.Since(startTime)
	throughput := float64(totalRecords) / elapsedTime.Seconds()
	fmt.Printf("Processed %d records in %s. Throughput: %.2f records/sec\n", totalRecords, elapsedTime, throughput)
	fmt.Printf("Total Rule Executions: %d\n", ruleExecutionCount)
}

func loadInputs(filePath string) []map[string]interface{} {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading input file: %v", err)
	}
	var inputs []map[string]interface{}
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		log.Fatalf("Error unmarshaling JSON data: %v", err)
	}
	return inputs
}
