import mongoose, { Schema } from "mongoose";

const subscriptionSchema = new Schema({
    subscriber: {
        type: Schema.Types.ObjectId,
        ref: "User"
    },
    channel: {
        // to whom the 'subscriber' is subscribing
        type: Schema.Types.ObjectId,
        ref: "User"
    },

}, { timestamps: true })


export const SubscriptionModel = mongoose.model("Subscriptions", subscriptionSchema);