# Robot-Monitoring-backend


## Creating and installing Self Signed Certificate 
**creating  Self-signed certificate in  Linux system:**
	
``` 
  sudo openssl genrsa -out server-cert.key 2048
  sudo openssl ecparam -genkey -name secp384r1 -out server-cert.key
  ```

once you create the key, you can execute below command and provide the information like country, state, servername, email;
  ```
 sudo openssl req -new -x509 -sha256 -key server-cert.key -out test-server.cert -days 3650
 ```

**How to use Self Signed Certificate using Gin Framework**

	
    router := gin.Default()
		router.GET("/home", abc)
		router.POST("/signup", registerUser)
		router.POST("/user", userAuth)	 
	       err := http.ListenAndServeTLS(":4001", "test-server.cert", "server-cert.key", router)
		if err != nil {
			log.Fatal(err)
		}
 
