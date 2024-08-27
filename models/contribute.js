import mongoose from 'mongoose'

const contributeSchema = new mongoose.Schema({
    name:{
        type:String,
    },
    email:{
        type:String,
    },
    message:{
        type:String,
    },
},{timestamps:true})

const Contribute = mongoose.model("contributions",contributeSchema)
export default Contribute