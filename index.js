if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
const express = require("express");
const session = require("express-session");
const multer = require("multer");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const path = require("path");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

app.set("view engine", "ejs");
app.set("views", "./views");
 
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/images");
  },
  filename: (req, file, cb) => {
    console.log(file);
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);

const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next(); // User is authenticated, let him in
  } else {
    res.redirect("/login"); // User is not authenticated, redirect to login page
  }
};

app.get("/", requireAuth, async (req, res) => {
    const posts = await prisma.post.findMany();

    const user = await prisma.user.findUnique({
        where: {
            id: req.session.userId,
        }, select: {
            role: true
        }
    });
    res.render("index", { posts,user});

});
app.get("/signup", (req, res) => {
    errors = [];
    res.render("signup", { errors });
});


app.post("/signup", upload.single("image"),async (req, res) => {
    const errors = [];
    const { username, password, email, vpassword, Admin } = req.body;
    const image = req.file ? `/images/${req.file.filename}` : null;
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    if (!username || !email || !password || !vpassword) {
        errors.push({ msg: "Please enter all fields" });
    }

    if (password != vpassword) {
        errors.push({ msg: "Passwords do not match" });
    }

    if (password.length < 6) {
        errors.push({ msg: "Password must be at least 6 characters" });
    }

    if (errors.length > 0) {
        res.render("signup", {
            errors: errors.map((error) => error.msg),
            username,
            email,
            image,
            password ,
            vpassword,
        });
    } else {
        try {
            const user = await prisma.user.create({
                data: {
                    username,
                    email,
                    password: hash,
                    role: Admin ? "ADMIN" : "USER",
                },
            });
            res.redirect("/");
        } catch (error) {
            // Handle error appropriately
            console.error(error);
            errors.push({ msg: "Error creating user. Please try again." });
            res.render("signup", { errors, username, email, password, vpassword });
        }
    }
});

app.get("/login", (req, res) => {
    errors = [];
    res.render("login", { errors });
});

app.post("/login", async (req, res) => {
    const errors = [];
    const { username, password } = req.body;
    if (!username || !password) {
        errors.push({ msg: "Please enter all fields" });
    }
    if (password.length < 6) {
        errors.push({ msg: "Password must be at least 6 characters" });
    }

    if (username.length > 20) {
        errors.push({ msg: "Username must be less than 20 characters" });
    }

    if (errors.length > 0) {
        res.render("login", {
            errors: errors.map((error) => error.msg),
            username,
            password,
        });
    } else {
        try {
            const user = await prisma.user.findUnique({
                where: {
                    username,
                },
            });
            if (user && user.password === bcrypt.hashSync(password, user.password)) {
                req.session.userId = user.id;
                req.session.role = user.role;
                res.redirect("/");
            } else {
                errors.push({ msg: "Invalid username or password" });
                res.render("login", { errors, username, password });
            }
        } catch (error) {
            // Handle error appropriately
            console.error(error);
            errors.push({ msg: "Error logging in. Please try again." });
            res.render("login", { errors, username, password });
        }
    }
});

app.get("/create",  requireAuth, (req, res) => {
    if (req.session.role === "ADMIN") {
        errors = [];
        res.render("create", { errors });
    } else {
        res.redirect("/");
    }
});

app.post("/create", upload.single("image"), requireAuth, async (req, res) => {
  const errors = [];
    const { title, description } = req.body;
    const image = req.file ? `/images/${req.file.filename}` : null;

  if (!title || !description) {
    errors.push({ msg: "Please enter all fields" });
  }

  if (errors.length > 0) {
    res.render("create", {
      errors: errors.map((error) => error.msg),
        title,
      description,
    });
  } else {
    try {
      const post = await prisma.post.create({
        data: {
          title,
              description,
          image,
          authorId: req.session.userId,
        },
      });
      res.redirect("/");
    } catch (error) {
      // Handle error appropriately
      console.error(error);
      errors.push({ msg: "Error creating post. Please try again." });
      res.render("create", { errors, title, description });
    }
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      res.redirect("/");
    } else {
      res.redirect("/login"); // Redirect to login or any desired page after logout
    }
  });
});

app.listen(3000, () => {
  console.log("Server started on port 3000");
});
