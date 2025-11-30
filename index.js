const express = require('express')
const cors = require('cors');
const app = express()
require('dotenv').config()
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_API_KEY)

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.PORT || 3000

// firebase service account
const admin = require("firebase-admin");

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// middlewares
app.use(express.json())
app.use(cors())

// tracking id generating
function generateTrackingId() {
    const prefix = 'ZAP';
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const random = crypto.randomBytes(3).toString("hex").toUpperCase()

    return `${prefix}-${date}-${random}`
}

// generating and verifying JWT token
const verifyFirebaseToken = async (req, res, next) => {

    const authorization = req.headers.authorization

    if (!authorization) {
        return res.status(401).json({ message: "Unauthorized access" })
    }

    const token = authorization.split(" ")[1]
    if (!token) {
        return res.status(401).json({ message: "Unauthorized access" })
    }

    try {
        const decoded = await admin.auth().verifyIdToken(token)
        req.decoded_email = decoded.email
        next()
    }
    catch (err) {
        return res.status(401).json({ message: "Unauthorized access" })
    }
}

// mongoDB connection uri
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@personal-hero.gxzvpbe.mongodb.net/?appName=Personal-Hero`;


const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // await client.connect();

        const db = client.db("zap_shift_db")
        const parcelsCollection = db.collection("parcels")
        const paymentCollection = db.collection('payments')
        const usersCollection = db.collection('users')
        const ridersCollection = db.collection('riders')
        const trackingsCollection = db.collection('trackings')

        // middleware with database access
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded_email;
            const query = { email }
            const user = await usersCollection.findOne(query)
            if (!user || user.role !== 'admin') {
                return res.status(403).json({ message: 'Forbidden access' })
            }
            next()
        }

        const verifyRider = async (req, res, next) => {
            const email = req.decoded_email;
            const query = { email }
            const user = await usersCollection.findOne(query)
            if (!user || user.role !== 'rider') {
                return res.status(403).json({ message: 'Forbidden access' })
            }
            next()
        }

        const logTracking = async (trackingId, status) => {
            const log = {
                trackingId,
                status,
                details: status.split(/[-_]/).join(' '),
                created_at: new Date()
            }

            const result = await trackingsCollection.insertOne(log)
            return result
        }

        app.get('/', (req, res) => {
            res.send("zapShift server is running")
        })

        // user related api

        app.get('/users', verifyFirebaseToken, async (req, res) => {
            const search = req.query.search;
            const query = {};

            if (search) {
                // query.displayName = { $regex: search, $options: 'i' }
                query.$or = [
                    { displayName: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } },
                ]
            }

            const result = await usersCollection.find(query).sort({ created_at: -1 }).limit(10).toArray()
            res.send(result)
        })

        app.get('/users/:id', async (req, res) => {

        })

        app.get('/users/:email/role', async (req, res) => {
            const email = req.params.email;
            const query = { email: email }
            const user = await usersCollection.findOne(query)

            res.send({ role: user.role || 'user' })
        })

        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = 'user';
            user.created_at = new Date()

            const userEmail = user.email

            const existingUser = await usersCollection.findOne({ email: userEmail })

            if (existingUser) {
                return res.send({ message: "User already exists" })
            }

            const result = await usersCollection.insertOne(user)

            res.send(result)
        })

        app.patch('/users/:id/role', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const roleInfo = req.body;
            const query = { _id: new ObjectId(id) }
            const updatedDoc = {
                $set: {
                    role: roleInfo.role
                }
            }

            const result = await usersCollection.updateOne(query, updatedDoc)

            res.send(result)
        })

        // product related api

        app.get("/parcels", async (req, res) => {
            try {
                const query = {}
                const email = req.query.email
                const deliveryStatus = req.query.deliveryStatus;

                if (email) {
                    query.senderEmail = email
                }

                if (deliveryStatus) {
                    query.delivery_status = deliveryStatus
                }

                const options = { sort: { created_at: -1 } }
                const result = await parcelsCollection.find(query, options).toArray()
                res.status(200).json({
                    fetch: "okay",
                    message: "Parcels data has been collected",
                    result
                })
            }
            catch (error) {
                res.status(500).json({
                    status: false,
                    message: "Couldn't find the parcels data",
                    error
                })
            }


        })

        app.get('/parcels/rider', async (req, res) => {
            const { riderEmail, delivery_status } = req.query;
            const query = {}
            if (riderEmail) {
                query.riderEmail = riderEmail
            }

            if (delivery_status !== 'parcel_delivered') {
                query.delivery_status = { $nin: ['parcel_delivered'] }
            } else {
                query.delivery_status = delivery_status
            }

            const result = await parcelsCollection.find(query).toArray()
            res.send(result)
        })

        app.get('/parcels/:id', async (req, res) => {
            const id = req.params.id
            const query = { _id: new ObjectId(id) }
            const result = await parcelsCollection.findOne(query)
            res.status(200).json(result)
        })

        // aggregation pipeline
        app.get('/parcels/delivery-status/stats', async (req, res) => {
            const pipeline = [
                {
                    $group: {
                        _id: '$delivery_status',
                        count: { $sum: 1 }
                    }
                },
                {
                    $project: {
                        status: '$_id',
                        count: 1
                    }
                }
            ]
            const result = await parcelsCollection.aggregate(pipeline).toArray()
            res.send(result)
        })

        app.post('/parcel', async (req, res) => {
            try {
                const parcel = req.body
                const trackingId = generateTrackingId()
                parcel.created_at = new Date()
                parcel.paymentStatus = "pending"
                parcel.trackingId = trackingId

                logTracking(trackingId, 'parcel_created')

                const result = await parcelsCollection.insertOne(parcel)
                res.status(200).json({
                    success: true,
                    message: "parcel has been added to database",
                    result
                })
            }
            catch {
                res.status(500).json({
                    status: false,
                    message: "couldn't send parcel to database"
                })
            }
        })

        app.patch('/parcels/assign_rider/:id', async (req, res) => {
            const { riderId, riderName, riderEmail, trackingId } = req.body;
            const id = req.params.id;
            const query = {
                _id: new ObjectId(id)
            }
            const updatedDoc = {
                $set: {
                    delivery_status: 'driver_assigned',
                    riderName: riderName,
                    riderEmail: riderEmail,
                }
            }

            const result = await parcelsCollection.updateOne(query, updatedDoc)

            const riderQuery = { _id: new ObjectId(riderId) }
            const riderUpdatedDoc = {
                $set: {
                    workStatus: 'in_delivery'
                }
            }
            const riderResult = await ridersCollection.updateOne(riderQuery, riderUpdatedDoc)

            logTracking(trackingId, 'driver_assigned')

            res.send(riderResult)
        })

        app.patch('/parcels/status/:id', async (req, res) => {
            try {
                const id = req.params.id
                const { delivery_status, riderEmail, trackingId } = req.body;
                const query = {
                    _id: new ObjectId(id)
                }
                const updatedDoc = {
                    $set: {
                        delivery_status: delivery_status
                    }
                }

                if (delivery_status === 'parcel_delivered') {
                    // update rider status
                    const riderQuery = { riderEmail: riderEmail }
                    const riderUpdatedDoc = {
                        $set: {
                            workStatus: 'available'
                        }
                    }
                    const riderResult = await ridersCollection.updateOne(riderQuery, riderUpdatedDoc)
                }

                const result = await parcelsCollection.updateOne(query, updatedDoc)

                logTracking(trackingId, delivery_status)

                res.send(result)
            }
            catch (err) {
                res.send({ message: "couldn't change driver status", err })
            }
        })

        app.delete('/parcel/:id', async (req, res) => {
            try {
                const id = req.params.id
                const query = {
                    _id: new ObjectId(id)
                }

                const result = await parcelsCollection.deleteOne(query)
                res.status(200).json({
                    delete: "success",
                    message: "successfully deleted parcel",
                    result
                })
            }
            catch {
                res.status(500).json({
                    delete: "failed",
                    message: "deletion unsuccessful"
                })
            }
        })

        // Payment related apis

        app.get('/payments', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.query.email;
                const query = {}
                if (email) {
                    query.customer_email = email

                    if (email !== req.decoded_email) {
                        return res.status(403).json({ message: "Forbidden access" })
                    }
                }
                const result = await paymentCollection.find(query).sort({ paidAt: -1 }).toArray()
                res.status(200).json({
                    success: true,
                    message: `Payment history of ${email} has been retrieved`,
                    result
                })
            }
            catch {
                res.status(500).json({
                    success: false,
                    message: `Failed to retrieve payment history of ${email}`
                })
            }
        })

        app.post('/create-checkout-session', async (req, res) => {
            const paymentInfo = req.body
            const amount = parseInt(paymentInfo.cost) * 100
            const session = await stripe.checkout.sessions.create({
                line_items: [
                    {
                        quantity: 1,
                        price_data: {
                            currency: 'usd',
                            unit_amount: amount,
                            product_data: {
                                name: paymentInfo.parcelName
                            },
                        }
                    }
                ],
                customer_email: paymentInfo.senderEmail,
                mode: 'payment',
                metadata: {
                    parcelId: paymentInfo.parcelId,
                    parcelName: paymentInfo.parcelName,
                    trackingId: paymentInfo.trackingId
                },
                success_url: `${process.env.SITE_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.SITE_URL}/dashboard/payment-cancel`
            })
            res.send({ url: session.url })
        })

        app.patch('/payment-success', async (req, res) => {
            try {
                const sessionId = req.query.session_id

                const session = await stripe.checkout.sessions.retrieve(sessionId)

                const transaction_id = session.payment_intent
                const query = { transaction_id: transaction_id }

                const paymentExist = await paymentCollection.findOne(query)
                if (paymentExist) {
                    return res.send({
                        message: "Payment already exist",
                        transaction_id,
                        trackingId: paymentExist.trackingId
                    })
                }

                const trackingId = session.metadata.trackingId;

                if (session.payment_status === 'paid') {
                    const parcelId = session.metadata.parcelId
                    const query = { _id: new ObjectId(parcelId) }

                    const update = {
                        $set: {
                            paymentStatus: 'paid',
                            delivery_status: 'parcel_paid'
                        }
                    }

                    const result = await parcelsCollection.updateOne(query, update)

                    const payment = {
                        amount: session.amount_total / 100,
                        currency: session.currency,
                        customer_email: session.customer_email,
                        parcelId: session.metadata.parcelId,
                        parcelName: session.metadata.parcelName,
                        transaction_id: session.payment_intent,
                        paymentStatus: session.payment_status,
                        paidAt: new Date(),
                        trackingId: trackingId
                    }

                    if (payment.paymentStatus === 'paid') {
                        const resultPayment = await paymentCollection.insertOne(payment);
                        logTracking(trackingId, 'parcel_paid')
                        res.json({
                            success: true,
                            modifyParcel: result,
                            paymentInfo: resultPayment,
                            trackingId,
                            transaction_id: session.payment_intent
                        })
                    }
                }
                res.send({ success: false })
            } catch {
                res.status(500).json({
                    success: false,
                    message: "payment failed"
                })
            }
        })

        // riders related apis

        app.get('/riders', async (req, res) => {
            const { status, district, workStatus } = req.query
            const query = {}
            if (status) {
                query.status = status
            }
            if (district) {
                query.riderDistrict = district
            }
            if (workStatus) {
                query.workStatus = workStatus
            }
            const result = await ridersCollection.find(query).toArray()

            res.send(result)
        })

        // aggregate pipeline
        app.get('/riders/delivery-per-day', async (req, res) => {
            const email = req.query.email;
            const pipeline = [
                {
                    $match: {
                        riderEmail: email,
                        delivery_status: 'parcel_delivered'
                    }
                },
                {
                    $lookup: {
                        from: 'trackings',
                        localField: 'trackingId',
                        foreignField: 'trackingId',
                        as: 'parcel_trackings'
                    }
                },
                {
                    $unwind: '$parcel_trackings'
                },
                {
                    $match: {
                        'parcel_trackings.status': 'parcel_delivered'
                    }
                },
                {
                    $addFields: {
                        deliveryDay: {
                            $dateToString: {
                                format: '%Y-%m-%d',
                                date: '$parcel_trackings.created_at'
                            }
                        }
                    }
                },
                {
                    $group: {
                        _id: '$deliveryDay',
                        deliveredCount: { $sum: 1 }
                    }
                }
            ]

            const result = await parcelsCollection.aggregate(pipeline).toArray()
            res.send(result)
        })

        app.post('/riders', async (req, res) => {
            const rider = req.body;
            rider.status = 'pending'
            rider.created_at = new Date()

            const result = await ridersCollection.insertOne(rider)

            res.send(result)
        })

        app.patch('/riders/:id', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const status = req.body.status
            const id = req.params.id
            const updatedDoc = {
                $set: {
                    status: status,
                    workStatus: 'available'
                }
            }
            const query = {
                _id: new ObjectId(id)
            }

            const result = await ridersCollection.updateOne(query, updatedDoc)

            if (status === 'approved') {
                const email = req.body.email;
                const userQuery = { email }

                const updateUser = {
                    $set: {
                        role: 'rider'
                    }
                }
                const userResult = await usersCollection.updateOne(userQuery, updateUser)
            }

            res.send({
                message: "updated riders",
                result
            })
        })

        // tracking related api
        app.get('/trackings/:trackingId/logs', async (req, res) => {
            try {
                const trackingId = req.params.trackingId;
                const query = { trackingId }

                const result = await trackingsCollection.find(query).toArray()

                res.send(result)
            }
            catch {
                res.send({ message: "couldn't find tracks of parcel" })
            }
        })


        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");

    } finally {

    }
}
run().catch(console.dir);

app.listen(port, () => {
    console.log("zapShift server is running on port:", port);
})