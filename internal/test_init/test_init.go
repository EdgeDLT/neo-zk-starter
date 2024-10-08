package test_init

import (
	"fmt"
	"os"
	"path"
	"runtime"
)

// init changes the working directory to the project root to
// make tests work with relative file paths
func init() {
	_, filename, _, _ := runtime.Caller(0)
	fmt.Println("Current file:", filename)
	dir := path.Join(path.Dir(filename), "../..")
	fmt.Println("Trying to change to directory:", dir)
	err := os.Chdir(dir)
	if err != nil {
		fmt.Println("Error changing directory:", err)
		panic(err)
	}
	currentDir, _ := os.Getwd()
	fmt.Println("Current working directory:", currentDir)
}
