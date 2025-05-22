# Yemeksepeti Clone - Fullstack

A full-stack clone of Yemeksepeti, featuring user authentication, restaurant listings, menus, cart, ordering, and dedicated panels for Admins, Restaurant Owners, and Couriers. This project demonstrates a complete food delivery application flow.

This project was developed by **12. Grup**.

## Features

*   **User Roles:**
    *   Customer: Browse restaurants, view menus, add to cart, place orders, view order history, manage profile.
    *   Restaurant Owner: Manage orders for their owned restaurant(s), update order statuses (e.g., "hazırlanıyor", "kuryeye verildi").
    *   Courier: View orders assigned for delivery (status "kuryeye verildi"), mark orders as "teslim edildi".
    *   Admin: View all users, restaurants, and orders. Can manage system-wide data (implicitly, as this panel is for viewing/overview).
*   **Authentication:** Secure login and registration for different user roles.
*   **Restaurant Listing & Search:** Browse all available restaurants, search for restaurants or specific food items.
*   **Menu Display:** View detailed menus for each restaurant.
*   **Shopping Cart:** Add/remove items, view cart total.
*   **Ordering System:** Place orders, which are then visible to restaurant owners and admins.
*   **Profile Management:** Users can update their personal information and change passwords.
*   **Responsive Design:** Basic responsiveness for various screen sizes.

## Tech Stack

*   **Frontend:**
    *   HTML5
    *   CSS3
    *   Vanilla JavaScript (ES6+)
*   **Backend:**
    *   Node.js
    *   Express.js
*   **Database:**
    *   SQLite

## Prerequisites

*   [Node.js](https://nodejs.org/) (v16 LTS or later recommended)
*   npm (comes with Node.js)

## Setup and Running

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/Yemeksepeti-Clone-Fullstack.git
    cd Yemeksepeti-Clone-Fullstack
    ```

2.  **Install backend dependencies:**
    Navigate to the project directory (where `app.js` and `package.json` are located) and run:
    ```bash
    npm install
    ```
    This will install Express, CORS, SQLite3, and bcrypt.

3.  **Start the backend server:**
    In the same directory, run:
    ```bash
    node app.js
    ```
    The server will start, typically on `http://localhost:3000`. You'll see a confirmation message in the terminal, including "DB bağlantısı başarılı."

4.  **Run the frontend:**
    Open the `index.html` file directly in your web browser (e.g., by double-clicking it or using "Open with..." from your file explorer).

    *   The frontend is configured to make API calls to `http://localhost:3000`.

## Screenshots

![Image Alt](https://github.com/cemrebayer/Yemeksepeti-Clone-Fullstack/blob/c1ff2642f6862e496692b17437ce39bbc4fe74fe/main%20screen.png)
![Image Alt](https://github.com/cemrebayer/Yemeksepeti-Clone-Fullstack/blob/c1ff2642f6862e496692b17437ce39bbc4fe74fe/order.png)
![Image Alt](https://github.com/cemrebayer/Yemeksepeti-Clone-Fullstack/blob/c1ff2642f6862e496692b17437ce39bbc4fe74fe/register.png)
![Image Alt](https://github.com/cemrebayer/Yemeksepeti-Clone-Fullstack/blob/c1ff2642f6862e496692b17437ce39bbc4fe74fe/restaurant%20order%20panel.png)
![Image Alt](https://github.com/cemrebayer/Yemeksepeti-Clone-Fullstack/blob/c1ff2642f6862e496692b17437ce39bbc4fe74fe/courier%20panel.png)

## Database

*   The application uses an SQLite database. The database file (`yemekapp.db`) will be automatically created in the project's root directory if it doesn't already exist when you start the backend server (`node app.js`).
*   On its first run (or if the database is empty/missing certain admin users), the server will also populate the database with sample data, including users for different roles, restaurants, and menu items. This ensures you have data to interact with immediately after setup.

## Default User Credentials (Sample Data)

The application creates the following sample users when the database is initialized:

*   **Admin:**
    *   Email: `admin@example.com`
    *   Password: `admin123`
*   **Restaurant Owner (General):**
    *   Email: `restaurant@example.com`
    *   Password: `password123`
*   **Restaurant Owner (Burger King):**
    *   Email: `burgerking@gmail.com`
    *   Password: `123456`
*   **Restaurant Owner (McDonald's):**
    *   Email: `mcdonalds@gmail.com`
    *   Password: `123456`
*   **Restaurant Owner (Popeyes):**
    *   Email: `popeyes@gmail.com`
    *   Password: `123456`
*   **Restaurant Owner (Starbucks):**
    *   Email: `starbucks@gmail.com`
    *   Password: `123456`
*   **Courier:**
    *   Email: `courier@example.com`
    *   Password: `courier123`

You can register new "Customer" and "Courier" accounts through the registration form on the frontend. "Restaurant Owner" and "Admin" registration is typically handled manually or via a separate admin interface in a production system; here, they are pre-seeded.

## Project Structure
