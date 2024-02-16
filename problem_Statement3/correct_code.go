package main

import (
	"fmt"
	"sync"
)

func Correct_code() {
	cnp := make(chan func(), 10)
	var wg sync.WaitGroup
	wg.Add(4)

	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done()
			for f := range cnp {
				f()
			}
		}()
	}
	cnp <- func() {
		fmt.Println("HERE1")
	}
	close(cnp)
	wg.Wait()

	fmt.Println("Hello")
}
