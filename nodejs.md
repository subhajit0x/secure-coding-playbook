# Node.js & MERN Stack

- **Input Validation and Data Sanitization:** Always sanitize and validate user inputs to prevent injection attacks.
    
    ```
    
    const sanitize = require('mongo-sanitize');
    
    app.post('/data', function(req, res) {
        // Potential vulnerability: User input is inserted directly into the database
        // Recommendation: Sanitize user input before inserting into the database
        let inputData = sanitize(req.body.inputData);
        db.collection('data').insertOne({ data: inputData }, function(err, result) {
            // handle err and result
        });
    });
    
    ```
    
- **Error Handling and Logging:** Proper error handling prevents the leaking of sensitive information.
    
    ```
    
    // Potential vulnerability: Detailed error information could be revealed to the user
    // Recommendation: Only provide minimal error information to the user
    app.use((err, req, res, next) => {
        console.error(err.stack); // Log the stacktrace for debugging
        res.status(500).send('Something broke!');
    });
    
    ```
    
- **Secure Session Management:** Use HTTPS and secure cookies to protect session IDs in transit.
    
    ```
    const express = require('express');
    const session = require('express-session');
    const cookieParser = require('cookie-parser');
    const app = express();
    
    app.use(cookieParser());
    
    // Potential vulnerability: Session ID could be intercepted during transmission
    // Recommendation: Use secure cookies and HTTPS for transmitting session IDs
    app.use(session({
        secret: 'Your_Secret_Key',
        cookie: {
            secure: true,
            httpOnly: true
        }
    }));
    
    ```
    
- **Use of Secure Headers:** Incorporate HTTP security headers to secure your application.
    
    ```
    const helmet = require('helmet');
    app.use(helmet());
    
    // Potential vulnerability: Not using proper HTTP headers could leave the application vulnerable to attacks
    // Recommendation: Use libraries like helmet to add secure headers to your application
    
    ```
    
- **Prevention of Brute-Force Attacks:** Implement rate-limiting to prevent brute-force attacks.
    
    ```
    const rateLimit = require("express-rate-limit");
    
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100 // limit each IP to 100 requests per windowMs
    });
    
    //  apply to all requests
    app.use(limiter);
    
    // Potential vulnerability: Not having rate-limiting allows brute-force attacks
    // Recommendation: Implement rate limiting on all API endpoints to prevent brute-force attacks
    
    ```
    
- **Avoiding eval():** **`eval()`** function is dangerous as it allows arbitrary code execution. Avoid using it whenever possible.
    
    ```
    let userControlledInput = /* user-controlled input */;
    
    // Potential vulnerability: eval() allows arbitrary code execution
    // Recommendation: Avoid using eval(), instead opt for safer alternatives
    // Insecure way
    // eval('console.log(' + userControlledInput + ')');
    // Secure way
    console.log(userControlledInput);
    
    ```
    
- **Preventing Prototype Pollution:** Prototype pollution can cause application crashes or unintended behavior. Always validate object keys and values.
    
    ```
    function merge(destinationObject, sourceObject) {
        for (let key in sourceObject) {
            // Potential vulnerability: Not checking if the object's keys are part of its prototype could lead to prototype pollution
            // Recommendation: Always check if the object's keys are part of its own properties to prevent prototype pollution
            if (sourceObject.hasOwnProperty(key)) {
                destinationObject[key] = sourceObject[key];
    	}
        return destinationObject;
    }
    ```
    
- **Protection Against Header Injection:** Avoid newline characters in HTTP headers.
    
    ```
    const express = require('express');
    const app = express();
    
    app.get('/', (req, res) => {
        let username = req.query.username || '';
    
        // Potential vulnerability: Header Injection
        // Recommendation: Remove newline characters from HTTP headers
        username = username.replace(/[\r\n]/g, '');
    
        res.setHeader('X-Username', username);
        res.end('Hello');
    });
    
    ```
    
- **Protection Against Insecure Deserialization:** Avoid serialization of sensitive data, especially when using it in cookies, and consider encrypting serialized data if you have to use it.
    
    ```jsx
    
    const express = require('express');
    const cookieParser = require('cookie-parser');
    const app = express();
    
    app.use(cookieParser());
    
    // Potential vulnerability: Insecure Deserialization
    // Recommendation: Avoid serializing sensitive data and consider encrypting serialized data
    // Assume "deserializeCookie" is a function you define to securely deserialize cookies
    // app.use(deserializeCookie);
    ```
    ```