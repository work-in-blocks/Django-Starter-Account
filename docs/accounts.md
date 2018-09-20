# Documentation of endpoint Accounts
## Login
Grants access to a user to start in Page or App

* Url

  http://127.0.0.1:8000/accounts/signin/

* Method

  **POST**

* Url Params

  **None**

* Data Params
    ```javascript
     {
        "username":"solrac",
        "password":"1234qwer"
     } 
    ```
 you can also send the mail

* Success Response:
   * code: 200
    ```javascript
   {
        "username": "solrac",
        "id": 2,
        "token": "a8ecf7bca9d730067acf44ceeb70ff28c1344472",
        "last_login": "2018-09-06T12:11:49.455580Z"
    }
   ```  
* Error Response:
   
   In case username or password incorrect 
  * code: 400
   ```javascript
   {
     "detail":"The username or password is incorrect"
   }
   ``` 
  or
  
  in case password is empty or do not send inside json
  * code: 400
   ```javascript
   {
     "detail":"The password cannot be empty"
   }
   ``` 
  or
  
  In case username is empty or do not send inside json
  * code: 400
   ```javascript
   {
     "detail":"The username cannot be empty"
   }
   ``` 
  or

  In case your accounts is inactive or blocked 
  * code: 401
  ```javascript
  {
    "detail": "Account inactive, or your account is blocked"
  }
  ```
* Notes:
 
  **None**

## Login with captcha
Grants access to a user to start in Page or App

* Url

  http://127.0.0.1:8000/accounts/signin-captcha/

* Method

  **POST**

* Url Params

  **None**

* Data Params
    ```javascript
     {
        "username":"solrac",
        "password":"1234qwer",
        "callback":"6asd6a6s5d16as1d"
     } 
    ```
 you can also send the mail

* Success Response:
   * code: 200
    ```javascript
    {
        "username": "solrac",
        "id": 2,
        "token": "a8ecf7bca9d730067acf44ceeb70ff28c1344472",
        "last_login": "2018-09-06T12:11:49.455580Z"
    }
   ```  
* Error Response:

   In case captcha empty 
  * code: 400
   ```javascript
   {
     "detail":"reCAPTCHA field cant not be empty"
   }
   ``` 
  or
  
  In case captcha is incorrect 
  * code: 400
   ```javascript
   {
     "detail":"Invalid reCAPTCHA. Please try again."
   }
   ``` 
  or
  
   In case username or password incorrect 
  * code: 400
   ```javascript
   {
     "detail":"The username or password is incorrect"
   }
   ``` 
  or
  
  in case password is empty or do not send inside json
  * code: 400
   ```javascript
   {
     "detail":"The password cannot be empty"
   }
   ``` 
  or
  
  In case username is empty or do not send inside json
  * code: 400
   ```javascript
   {
     "detail":"The username cannot be empty"
   }
   ``` 
  or

  In case your accounts is inactive or blocked 
  * code: 401
  ```javascript
  {
    "detail": "Account inactive, or your account is blocked"
  }
  ```
* Notes:
 
  **None**

## Login with facebook
Grants access to a user to start in Page or App

* Url

  http://127.0.0.1:8000/accounts/signin-facebook/

* Method

  **POST**

* Url Params

  **None**

* Data Params
    ```javascript
     {
        "access_token":"EAACxfwbiBU8BAP873rRdjdbsGJoBrAjmPOf3HCV00elJRdJuY5skotXEh4orZApi04HeowSMRVd4ZAAkF7VDZBZCl2HGpZAZBkqDJeZAKyZCgZAAAKa8wnSh2moa6ZBEJ5FmJABm90V5DxjRZA2vsWokcsTW13RI5kvQ09F4qv0uOrfZAJhqa8NKt8khnueNQp6XGJ0ZD"
     } 
    ```

* Success Response:
   * code: 200
    ```javascript
   {
        "username": "carlos5_zeta123",
        "id": 2,
        "token": "a8ecf7bca9d730067acf44ceeb70ff28c1344472",
        "last_login": ""
    }
   ```  
* Error Response:
   
   In case access token facebook dont belong to this user 
  * code: 400
   ```javascript
    {
        "detail": "The access token does not belong to that user"
    }
   ``` 
  or
  
  in case problem to save user
  * code: 400
   ```javascript
   {
     "detail":"An error occurred while saving the user"
   }
   ``` 
* Notes:
 
  **None**
  
## Logout
Logout the user in app

**Token is required**

* Url

  http://127.0.0.1:8000/accounts/logout/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "You have disconnected from the system"
   }
   ```  
* Error Response:
  * code: 400
   ```javascript
   {
     "detail":"A Valid and Active User must be provided""
   }
   ``` 
   or
   * code: 401
   ```javascript
   {
     "detail":"Invalid token."
   }
   ``` 
* Notes:
 
  **None**

## Register
Register a user in app

* Url

  http://127.0.0.1:8000/accounts/signup/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
  ``` javascript
    {
        "username":"lomax120",
        "password":"car1234",
        "first_name":"carlos",
        "last_name":"olivero",
        "email":"fce07311ef@mailox.biz",
        "sex":"Men",
        "age": "1992-08-02",
        "phone": "+584146419077"
    }
  ```  
    
* Success Response:
   * code: 201
    ```javascript
    {
        "detail": "The creation of your account has been successfully completed",
        "username": "lomax120"
    }
    ```  
* Error Response:
  * code: 400
   ```javascript
    {
      {
       "detail": {
        "age": [
            "The date you entered is not valid",
            "empty values not allowed"
        ],
        "email": [
            "Please enter a valid email address",
            "empty values not allowed"
        ],
        "first_name": [
            "empty values not allowed"
        ],
        "last_name": [
            "empty values not allowed"
        ],
        "password": [
            "empty values not allowed"
        ],
        "phone": [
            "empty values not allowed"
        ],
        "sex": [
            "empty values not allowed"
        ],
        "username": [
            "empty values not allowed"
        ]
      }
    }
   ``` 
   or
   * code: 400
   ```javascript
   {
        "detail": {
            "email": "Mail exists, please enter another email"
        }
    }
   ``` 
* Notes:
 
  **None**

## Password recovery by email
Recover password with the email of user

* Url

  http://127.0.0.1:8000/accounts/request-password-email/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
  ```javascript
   {  
  	 "email":"carlos5_zeta@hotmail.com"
   }
  ```  
* Success Response:
   * code: 200
    ```javascript
    {
      "detail": "The code has been sent successfully"
    }
   ```  
* Error Response:
   
   In case email if empty
   * code: 400
   ```javascript
   {
     "detail":"The email field can not be empty"
   }
   ``` 
   or
   
   In case the email does not exist in app
   * code: 400
   ```javascript
   {
     "detail":"The email is not registered in the system"
   }
   ``` 
   or
   
   In case the user is block or inactive
   * code: 400
   ```javascript
   {
     "detail":"In order to perform this operation, your account must be active"
   }
   ``` 
* Notes:
 
  **This endpoint send a code to email selected and with this code recover password**

## Password recovery by phone
Recover password with the phone number of user

* Url

  http://127.0.0.1:8000/accounts/request-password-phone/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params

  The username can also be email
  ```javascript
   {
	    "username":"solrac5",
	    "phone":"+5804146419077"
   }
  ```  
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "The code has been sent successfully"
   }
   ```  
* Error Response:
  * code: 400
  
  Phone number is empty
   ```javascript
   {
     "detail":"Phone number field is required"
   }
   ``` 
   username is empty
   ```javascript
   {
     "detail":"Username field is required"
   }
   ``` 
   or
   
   In case phone number don`t belong to this user
   * code: 400
   ```javascript
   {
     "detail":"phone number incorrect"
   }
   ``` 
   or
   
   In case the user is block or inactive
   * code: 400
   ```javascript
   {
     "detail":"In order to perform this operation, your account must be active"
   }
   ```
* Notes:
 
  **This endpoint send a message wiht the code to phone number selected, to recover password**
 
 ## Password recovery
Recover password with the received code

* Url

  http://127.0.0.1:8000/accounts/recover-password/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
   ```javascript
    {
	    "code":"1ZH7ITFY",
	    "password":"car1234"
    }
   ```   
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "The password has been successfully changed"
   }
   ```  
* Error Response:
  * code: 400
   
   In case password is empty 
   ```javascript
   {
     "detail":"The password field cannot be empty"
   }
   ``` 
   or
   
   In case code is empty
   * code: 400
   ```javascript
   {
     "detail":"The code field cannot be empty"
   }
   ```
   or
   
   In case user is inactive or block
   * code: 400
   ```javascript
   {
     "detail":"In order to perform this operation, your account must be active"
   }
   ``` 
   or
   
   In case code don`t belong to this user
   * code: 400
   ```javascript
   {
     "detail":"Code you sent does not match the one registered in your account"
   }
   ```  
* Notes:
 
  **None**

## Group
### View List
View list of group register in app, only admin user have access in app

**Token is required**

* Url

  http://127.0.0.1:8000/groups/

* Method

  **GET**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
    "count": 3,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 3,
            "name": "Vip",
            "permission": []
        },
        {
            "id": 2,
            "name": "Normal",
            "permission": [
                {
                    "id": 25,
                    "name": "Can add city",
                    "codename": "add_city"
                },
                {
                    "id": 26,
                    "name": "Can change city",
                    "codename": "change_city"
                }
            ]
        },
        {
            "id": 1,
            "name": "Admin",
            "permission": []
        },
       ]
   }
   ```  
* Error Response:
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
   ```javascript
   {
     "detail": "You do not have permission to perform this action."
   }
   ``` 
* Notes:
 
  **None**

## Group
### View One
View one group register in app, only admin user have access in app 

**Token is required**

* Url

  http://127.0.0.1:8000/groups/id/
  
  **id = group id **

* Method

  **GET**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
        "id": 5,
        "name": "Normal",
        "permission": [
            {
                "id": 25,
                "name": "Can add city",
                "codename": "add_city"
            },
            {
                "id": 26,
                "name": "Can change city",
                "codename": "change_city"
            }
        ]
   }
   ```  
* Error Response:
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
   or
  
  * code: 403
   ```javascript
   {
     "detail": "You do not have permission to perform this action."
   }
   ``` 
   or
   
  * code: 404
   ``` javascript
   {
     "detail": "Not found."
   }
   ```
   
* Notes:
 
  **None**

## Group
### Create
Create group in app, only admin user have access in app

**Token is required**

* Url

  http://127.0.0.1:8000/groups/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
   ```javascript  
   {
	    "name": "TravelVip"
   }
  ``` 
* Success Response:
   * code: 200
    ```javascript
   {
        "id": 7,
        "name": "TravelVip",
        "permission": [],
        "detail": "You have successfully added a group to admin server"
   }
   ```  
* Error Response:

   In case group name is empty
   * code: 400
   
   ```javascript
   {
     "detail": "Group name cannot be empty"
   }
   ``` 
  or
  
  In case group name already exist
  * code: 400
   ```javascript
   {
     "detail": "Group name exists try by another name"
   }
   ``` 
  or
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
   ```javascript
   {
     "detail": "You do not have permission to perform this action."
   }
   ``` 
* Notes:
 
  **None**

## Group
### Update
Edit group register in app, only admin user have access in app

**Token is required**

* Url

  http://127.0.0.1:8000/groups/id/
  
  **id = group id**
  
* Method

  **PUT**

* Url Params
  
  **None**

* Data Params
   ```javascript  
   {
	    "name": "Travel"
   }
  ```
  
* Success Response:
   * code: 200
    ```javascript
   {
        "id": 6,
        "name": "Travel1",
        "permission": [],
        "detail": "Your group information has been successfully edited"
   }
   ```  
* Error Response:
  
  In case group name is empty
  * code: 400
   ```javascript
   {
     "detail": "Group name cannot be empty"
   }
   ``` 
  or
  
  In case group name already exist
  * code: 400
   ```javascript
   {
     "detail": "Group name exists try by another name"
   }
   ``` 
  or
  
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
   ```javascript
   {
     "detail": "You do not have permission to perform this action."
   }
   ```
  or
   
  * code: 404
   ``` javascript
   {
     "detail": "Not found."
   }
   ``` 
* Notes:
 
  **None**

## Group
### Delete
Delete group in app, only admin user have access in app 

**Token is required**

* Url

  http://127.0.0.1:8000/groups/id/
  
  **id = group id**

* Method

  **DELETE**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "Group has been successfully deleted"
   }
   ```  
* Error Response:
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
   ```javascript
   {
     "detail": "You do not have permission to perform this action."
   }
   ``` 
  or
  
  * code: 404
   ``` javascript
   {
     "detail": "Not found."
   }
   ```
* Notes:
 
  **None**

## Group
### Add Permission
Add new permission to group selected, only admin user have access in app 

**Token is required**

* Url

  http://127.0.0.1:8000/groups/id/add-permission/id/
  
  **id = group id**
  
  **id = permission id**
  
* Method

  **PUT**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
        "id": 7,
        "name": "TravelVip",
        "permission": [
            {
                "id": 45,
                "name": "Can view car",
                "codename": "view_car"
            }
        ],
        "detail": "You have add new permission to selected group"
   }
   ```  
* Error Response:
   
  In case permission id does not exist
  * code: 400
   ```javascript
   {
     "detail": "Permission does not exist"
   }
   ``` 
  or
  
  In case permission has already benn added to the group
  * code: 400
   ```javascript
   {
     "detail": "Permission has already been added to this group"
   }
   ``` 
  or
  
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
   ```javascript
   {
     "detail": "You do not have permission to perform this action."
   }
   ```
  or
  
  * code: 404
   ``` javascript
   {
     "detail": "Not found."
   }
   ```  
* Notes:
 
  **None**

## Group
### Delete Permission
delete permission to group selected, only admin user have access in app

**Token is required**

* Url

  http://127.0.0.1:8000/groups/id/delete-permission/id/
  
  **id = group id**
  
  **id = permission id**

* Method

  **DELETE**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
        "id": 7,
        "name": "TravelVip",
        "permission": [],
        "detail": "You have delete permission to selected group"
    }
   ```  
* Error Response:
  
  In case permission id does not exist
  * code: 400
   ```javascript
   {
     "detail": "Permission does not exist"
   }
   ``` 
  or
  
  In case group don`t have any permission
 * code: 400
   ```javascript
   {
     "detail": "Group don`t have any permission to delete"
   }
   ``` 
  or
  
  In case permission does not exist in the group
 * code: 400
   ```javascript
   {
     "detail": "The permission to delete does not exist inside the group"
   }
   ``` 
  or
  
 * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
  or
  
  * code: 404
     ``` javascript
    {
        "detail": "Not found."
    }
     ``` 
* Notes:
 
  **None**
  
## Permission
### View List
Get list with all permission register in app, only admin user have access in app

* Url

  http://127.0.0.1:8000/permission/

* Method

  **GET**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
    "count": 43,
    "next": "http://127.0.0.1:8000/permission/?page=2",
    "previous": null,
    "results": [
        {
            "id": 47,
            "name": "Can add car",
            "codename": "add_car"
        },
        {
            "id": 46,
            "name": "Can add card",
            "codename": "add_card"
        },
        {
            "id": 45,
            "name": "Can view car",
            "codename": "view_car"
        },
        {
            "id": 40,
            "name": "Can view Token",
            "codename": "view_token"
        },
       ]
    }
   ```  
* Error Response:
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
* Notes:
 
  **None**

## Permission
### View One
Get only one permission, only admin user have access in app

* Url

  http://127.0.0.1:8000/permission/id/
  
  **id = permission id**

* Method

  **GET**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
        "id": 2,
        "name": "Can change log entry",
        "codename": "change_logentry"
   }
   ```  
* Error Response:
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
  or
  
  * code: 404
     ``` javascript
    {
        "detail": "Not found."
    }
     ```
* Notes:
 
  **None**
  
## Permission
### Create
Create a new permission in app, only admin user have access in app

* Url

  http://127.0.0.1:8000/permission/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
  ``` javascript  
  {
	"name":"Can delete car ",
	"codename":"delete_car"
  }
  ```
  
* Success Response:
   * code: 200
    ```javascript
   {
        "id": 48,
        "name": "Can delete car ",
        "codename": "delete_car",
        "detail": "Permission have successfully added"
   }
   ```  
* Error Response:
  * code: 400
   ```javascript
   {
     "detail": "Permission name cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Code name cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Permission name or code name exists try by another name"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "An error occurred while saving permission"
   }
   ``` 
  or
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
* Notes:
 
  **None**
  
## Permission
### Update
update permission in app, only admin user have access in app

* Url

  http://127.0.0.1:8000/permission/id/
  
  **id = permission id**

* Method

  **PUT**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
   {
        "id": 48,
        "name": "Can delete car ",
        "codename": "delete_car",
        "detail": "Permission has been successfully edited"
    }
   ```  
* Error Response:
  * code: 400
   ```javascript
   {
     "detail": "Permission name cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Code name cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Permission name or code name exists try by another name"
   }
   ``` 
  or
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
  or
  
  * code: 404
     ``` javascript
    {
        "detail": "Not found."
    }
     ```
* Notes:
 
  **None**
 
## Permission
### Delete
Delete permission in app, only admin user have access in app

* Url

  http://127.0.0.1:8000/permission/id/
  
  **id = permission id**

* Method

  **DELETE**

* Url Params
  
  **None**

* Data Params
    
  **None**
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "Permission has been successfully deleted"
   }
   ```  
* Error Response:
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
  or
  
  * code: 404
     ``` javascript
    {
        "detail": "Not found."
    }
     ```
* Notes:
 
  **None**

## User Group
### Add
add group into user selected, only admin user have access in app

* Url

  http://127.0.0.1:8000/accounts/group/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
  ```javascript
   {
	    "user_id":"2",
	    "group_id":"5"
   }
  ```
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "You have add the user to group Vip"
   }
   ```  
* Error Response:
  * code: 400
   ```javascript
   {
     "detail": "User id cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Group id cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "User id or group is not a number"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Group you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "User you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "This user already has this group added"
   }
   ``` 
  or
  
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
* Notes:
 
  **None**
  
## User Group
### Delete
Delete group into user selected, only admin user have access in app

* Url

  http://127.0.0.1:8000/accounts/group/

* Method

  **DELETE**

* Url Params
  
  **None**

* Data Params
  ```javascript
   {
	    "user_id":"2",
	    "group_id":"5"
   }
  ```
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "You have remove the user the group Vip"
   }
   ```  
* Error Response:
  * code: 400
   ```javascript
   {
     "detail": "User id cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Group id cannot be empty"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "User id or group is not a number"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "Group you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "User you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "This user does not have any group to deleted"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "This group has been removed for this user or has never been added"
   }
   ``` 
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
* Notes:
 
  **None**
 
## User Permission
### Add
add permission into user selected, only admin user have access in app

* Url

  http://127.0.0.1:8000/accounts/permission/

* Method

  **POST**

* Url Params
  
  **None**

* Data Params
  ``` javascript
    {
	    "user_id": "2",
	    "permission_id": "40"
    }
  ```  
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "You have added permission to the user"
   }
   ```  
* Error Response:
  * code: 400
   ```javascript
   {
     "detail": "User id cannot be empty"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "Permission id cannot be empty"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "User id or permission is not a number"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "Permission you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "User you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "This user already has this permission added"
   }
   ``` 
  or
  
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
* Notes:
 
  **None**
 
## User Permission
### Delete
Delete permission into user selected, only admin user have access in app

* Url

  http://127.0.0.1:8000/accounts/permission/

* Method

  **DELETE**

* Url Params
  
  **None**

* Data Params
  ``` javascript
    {
	    "user_id": "2",
	    "permission_id": "40"
    }
  ```  
  
* Success Response:
   * code: 200
    ```javascript
   {
     "detail": "You have remove the user the permission"
   }
   ```  
* Error Response:
  * code: 400
   ```javascript
   {
     "detail": "User id cannot be empty"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "Permission id cannot be empty"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "User id or permission is not a number"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "Permission you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "User you search does not exist"
   }
   ``` 
  or
  
  * code: 400
   ```javascript
   {
     "detail": "This user does not have any permission to deleted"
   }
   ``` 
  or
  * code: 400
   ```javascript
   {
     "detail": "This permission has been removed for this user or has never been added"
   }
   ``` 
  or
  
  * code: 401
   ```javascript
   {
     "detail": "Authentication credentials were not provided."
   }
   ``` 
  or
  
  * code: 403
    ```javascript
    {
        "detail": "You do not have permission to perform this action."
    }
    ```
* Notes:
 
  **None**