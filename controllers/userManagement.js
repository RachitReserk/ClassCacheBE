import express from 'express';
const userRouter = express.Router();

import User from '../models/user.js'
import bcrypt from 'bcryptjs'
import  jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
dotenv.config()

import authenticateToken from '../utils/userAuth.js'
import transporter from '../utils/noidemailer.js';

userRouter.post('/sign-up',async(req,res) =>{
    try {
      const emailDomain = '@juitsolan.in';
    const {username , email , password , address} = req.body
    if(username.length < 5){
        return res
        .status(400)
        .json({message:"⚠️ Username should be greater than 4"})
    }
    const existingUsername = await User.findOne({username:username})
    if(existingUsername){
        return res
        .status(400)
        .json({message:"⚠️ Username already exists"})
     }
     const existingEmail = await User.findOne({email:email})
     if(existingEmail){
        return res
        .status(400)
        .json({message:"⚠️ Email already exists"})
     }
     if(password.length < 5){
        return res
        .status(400)
        .json({message:"⚠️ Password length should be more than 5"})
     }
     if(!email.endsWith(emailDomain)){
      return res
        .status(400)
        .json({message:"⚠️ Email should belong to JUIT's domain"})
     }


     const hashedPassword = await bcrypt.hash(password,10)

     const newUser = new User({username:username,email:email,password:hashedPassword,address:address})
     
     newUser.generateVerificationToken();
     await newUser.save();
     const verificationLink = `${process.env.WEB_URL}/${newUser.verificationToken}`
     await transporter.sendMail({
      to:newUser.email,
      subject:"ClassCache Email Verification",
      html:`<p>Click <a href="${verificationLink}">here</a> to verify your email for ClassCache.</p>`
     })

     return res.status(200).json({message:"Verification email sent"})     
    } catch (error)
    {
      return res.status(500).json({error:error ,message:"Internal server error"}) 
    }
})

userRouter.get('/verify-email/:token',async(req,res) => {
try{
const {token} = req.params
const user = await User.findOne({
   verificationToken:token,
   verificationTokenExpires:{$gt:Date.now()}
})

if (!user) return res.status(400).send('Invalid or expired token');

user.isVerified = true;
user.verificationToken = undefined;
user.verificationTokenExpires = undefined;
await user.save()
return res.status(200).json({message:"Verification Done"})     
}
catch(error){
   return res.status(500).json({message:"Verification error"}) 
}
})

userRouter.post('/sign-in',async(req,res) => {
   try {
      const {username,password} = req.body
      const existingUser = await User.findOne({username})
      if(!existingUser){
        return res.status(400).json({message:"Invalid credentials"})
      }
      if(existingUser.isVerified === false){
         return res.status(400).json({message:"❌ Email unverified"})
      }
      await bcrypt.compare(password,existingUser.password,(err,data) =>{
         if(data){
            const authClaims = [
               {name:existingUser.username},
               {role:existingUser.role}
            ]

            const token = jwt.sign({authClaims},process.env.KEY,{expiresIn:"7d"})
            res.status(200).json({id:existingUser.id,role:existingUser.role,token:token})
         }
         else{
            res.status(400).json({message:"Invalid  Credentials"})
         }
      })
   } catch (error
   ) {
      return res.status(500).json({message:"Internal server error"})
   }
})

userRouter.get('/userInfo',authenticateToken,async (req,res) => {
   try {
      const {id} = req.headers
      const data = await User.findById(id).select("-password")
      res.status(200).json(data)
      
   } catch (error) {
      return res.status(500).json({message:"Internal server error"})
   }
})

userRouter.put('/updateAddress',authenticateToken , async(req,res) => {
try {
   const {id} = req.headers
   const {address} = req.body
   await User.findByIdAndUpdate(id,{address: address})
   res.status(200).json({message:"address updated"})
} catch (error) {
   return res.status(500).json({message:"Internal server error"})
}
})

export default userRouter