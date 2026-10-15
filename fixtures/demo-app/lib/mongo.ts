import { MongoClient } from 'mongodb'

const client = new MongoClient(process.env.MONGODB_URI!)

export async function getCollection(name: string) {
  await client.connect()
  return client.db('legacy').collection(name)
}
