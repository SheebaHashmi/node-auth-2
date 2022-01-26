const router = require("express").Router();
const { checkUsernameExists, validateRoleName,checkRole } = require('./auth-middleware');
const helpers = require('../users/users-model')
const bcrypt = require('bcryptjs')
const { JWT_SECRET,tokenMaker } = require("../secrets");
const jwtDecode = require('jwt-decode')
 // use this secret!

router.post("/register", validateRoleName,(req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try{
    let {username,password} = req.body
    const hash = bcrypt.hashSync(password, 8)

  helpers.add({
      username,
      password:hash,
      role_name:req.role_name
    })
    next({status: 201,message: req.body})
    
  }
  catch(err){
    next(err)
  }
});


router.post("/login",checkUsernameExists,checkRole,(req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    let {password} = req.body
    if(bcrypt.compareSync(password , req.user.password)){
      const token = tokenMaker({...req.user,role_name:req.role_name})
 
        res.status(200).json({message:`${req.user.username} is back`,token})

    }else{
      res.status(401).json({message:'Invalid credentials'})
    }
  

 
});

module.exports = router;
