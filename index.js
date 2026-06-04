const express = require('express')
const fs = require('fs')
const path = require('path')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const app = express()
app.use(cors())
app.use(express.json())

const DB = path.join(__dirname,'db.json')
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret'

// Read and write a simple JSON-backed datastore for ideas, users, and interactions.
function readDB(){ return JSON.parse(fs.readFileSync(DB)) }
function writeDB(d){ fs.writeFileSync(DB, JSON.stringify(d,null,2)) }

function generateId(){ return Date.now().toString(36) + Math.random().toString(36).slice(2,8) }

app.post('/api/auth/register', async (req,res)=>{
  const db = readDB()
  const {name,email,photoURL,password} = req.body
  if(db.users.find(u=>u.email===email)) return res.status(400).json({message:'Email exists'})
  const hash = await bcrypt.hash(password,10)
  const user = {id: generateId(), name, email, photoURL, password:hash}
  db.users.push(user)
  writeDB(db)
  const token = jwt.sign({id:user.id,email:user.email,name:user.name}, JWT_SECRET)
  res.json({token, user:{id:user.id,name:user.name,email:user.email,photoURL:user.photoURL}})
})

app.post('/api/auth/login', async (req,res)=>{
  const db = readDB()
  const {email,password} = req.body
  const user = db.users.find(u=>u.email===email)
  if(!user) return res.status(400).json({message:'Invalid'})
  const ok = await bcrypt.compare(password,user.password)
  if(!ok) return res.status(400).json({message:'Invalid'})
  const token = jwt.sign({id:user.id,email:user.email,name:user.name}, JWT_SECRET)
  res.json({token, user:{id:user.id,name:user.name,email:user.email,photoURL:user.photoURL}})
})

// Protect routes by verifying the JWT token from the Authorization header.
function auth(req,res,next){
  const h = req.headers.authorization
  if(!h) return res.status(401).json({message:'Unauthorized'})
  const token = h.split(' ')[1]
  try{
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = payload
    next()
  }catch(e){ res.status(401).json({message:'Invalid token'}) }
}

// Retrieve ideas with optional text, category, and date range filtering.
app.get('/api/ideas', (req,res)=>{
  const db = readDB()
  let ideas = db.ideas.slice().reverse()
  const {limit, q, category, from, to} = req.query
  if(q) ideas = ideas.filter(i => i.title.toLowerCase().includes(q.toLowerCase()))
  if(category) ideas = ideas.filter(i => i.category === category)
  if(from) ideas = ideas.filter(i => new Date(i.createdAt) >= new Date(from))
  if(to) ideas = ideas.filter(i => new Date(i.createdAt) <= new Date(to))
  if(limit) ideas = ideas.slice(0, Number(limit))
  res.json(ideas)
})

app.get('/api/ideas/:id', (req,res)=>{
  const db = readDB()
  const idea = db.ideas.find(i=>i.id===req.params.id)
  if(!idea) return res.status(404).json({message:'Not found'})
  res.json(idea)
})

app.post('/api/ideas', auth, (req,res)=>{
  const db = readDB()
  const i = req.body
  const idea = { ...i, id: generateId(), authorId: req.user.id, authorName: req.user.name, comments: [], createdAt: new Date().toISOString() }
  db.ideas.push(idea)
  writeDB(db)
  res.json(idea)
})

// Allow idea owners to update their own idea fields.
app.put('/api/ideas/:id', auth, (req,res)=>{
  const db = readDB()
  const idea = db.ideas.find(i=>i.id===req.params.id && i.authorId===req.user.id)
  if(!idea) return res.status(404).json({message:'Not found or not owner'})
  Object.assign(idea, {
    title: req.body.title || idea.title,
    shortDescription: req.body.shortDescription || idea.shortDescription,
    detailedDescription: req.body.detailedDescription || idea.detailedDescription,
    category: req.body.category || idea.category,
    tags: req.body.tags || idea.tags,
    imageURL: req.body.imageURL || idea.imageURL,
    estimatedBudget: req.body.estimatedBudget || idea.estimatedBudget,
    targetAudience: req.body.targetAudience || idea.targetAudience,
    problemStatement: req.body.problemStatement || idea.problemStatement,
    proposedSolution: req.body.proposedSolution || idea.proposedSolution,
  })
  writeDB(db)
  res.json(idea)
})

app.get('/api/ideas/mine', auth, (req,res)=>{
  const db = readDB()
  const mine = db.ideas.filter(i=>i.authorId===req.user.id)
  res.json(mine)
})

app.delete('/api/ideas/:id', auth, (req,res)=>{
  const db = readDB()
  const idx = db.ideas.findIndex(i=>i.id===req.params.id && i.authorId===req.user.id)
  if(idx===-1) return res.status(404).json({message:'Not found or not owner'})
  db.ideas.splice(idx,1)
  writeDB(db)
  res.json({ok:true})
})

app.post('/api/ideas/:id/comments', auth, (req,res)=>{
  const db = readDB()
  const idea = db.ideas.find(i=>i.id===req.params.id)
  if(!idea) return res.status(404).json({message:'Not found'})
  const comment = { id: generateId(), userId: req.user.id, userName: req.user.name, text: req.body.text, createdAt: new Date().toISOString() }
  idea.comments = idea.comments || []
  idea.comments.push(comment)
  db.interactions.push({ type: 'comment', ideaId: idea.id, ideaTitle: idea.title, userId: req.user.id, at: new Date().toISOString() })
  writeDB(db)
  res.json(comment)
})

// Enable users to edit their own comments and keep interactions updated.
app.put('/api/ideas/:id/comments/:commentId', auth, (req,res)=>{
  const db = readDB()
  const idea = db.ideas.find(i=>i.id===req.params.id)
  if(!idea) return res.status(404).json({message:'Idea not found'})
  const comment = (idea.comments || []).find(c=>c.id===req.params.commentId && c.userId===req.user.id)
  if(!comment) return res.status(404).json({message:'Comment not found'})
  comment.text = req.body.text || comment.text
  writeDB(db)
  res.json(comment)
})

// Allow users to remove their own comments from an idea.
app.delete('/api/ideas/:id/comments/:commentId', auth, (req,res)=>{
  const db = readDB()
  const idea = db.ideas.find(i=>i.id===req.params.id)
  if(!idea) return res.status(404).json({message:'Idea not found'})
  const idx = (idea.comments || []).findIndex(c=>c.id===req.params.commentId && c.userId===req.user.id)
  if(idx===-1) return res.status(404).json({message:'Comment not found'})
  idea.comments.splice(idx,1)
  writeDB(db)
  res.json({ok:true})
})

app.get('/api/interactions/mine', auth, (req,res)=>{
  const db = readDB()
  const inter = db.interactions.filter(it=>it.userId===req.user.id)
  res.json(inter)
})

// Endpoint for users to update profile details such as name and photo URL.
app.put('/api/auth/profile', auth, (req,res)=>{
  const db = readDB()
  const user = db.users.find(u=>u.id===req.user.id)
  if(!user) return res.status(404).json({message:'User not found'})
  user.name = req.body.name || user.name
  user.photoURL = req.body.photoURL || user.photoURL
  writeDB(db)
  const updated = { id:user.id, name:user.name, email:user.email, photoURL:user.photoURL }
  res.json(updated)
})

// Serve client static files if present (for single-repo deployment)
const publicDir = path.join(__dirname, 'public')
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir))
  app.get('*', (req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'))
  })
}

const port = process.env.PORT || 5000
app.listen(port, ()=>console.log('Server running on', port))
