package policies

default message = ""

message := "Hello World" {
    input.is_hello == true
} 
message := "Hello World" {
    input.is_world == true
}
