=== INSTALL DEPENDENCIES ===
npm init -y
npm install express sqlite3
npm install -D typescript ts-node-dev
npm install nodemon


=== RUN ===
npx nodemon server.ts


=== Docker ===
docker build . -t tripbooking
docker run -d --name tripbooking -p 8888:3000  tripbooking
