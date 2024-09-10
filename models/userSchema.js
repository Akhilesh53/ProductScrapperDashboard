import mongoose from "mongoose";
import passportLocalMongoose from "passport-local-mongoose";

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: {
        type: String,
        select: false   
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date
})

userSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
export default mongoose.model('User', userSchema, 'users');