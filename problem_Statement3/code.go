package main

import "fmt"

func main() {
	cnp := make(chan func(), 4)
	for i := 0; i < 4; i++ {
		go func() {
			for f := range cnp {
				f()
			}
		}()
	}
	cnp <- func() {
		fmt.Println("HERE1")
	}
	close(cnp)
	Correct_code()
	fmt.Println("Hello")
}
