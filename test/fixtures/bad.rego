package badpolicy

default allow := true

password := "supersecret123"

violation[msg] {
    print("checking something")
    msg := "this is bad"
}
