const bookshelf = require('../bookshelf');

// creating the Product model
// one model is for one table in the database
// first argument is the name of the model
// convention: use the singular form of the table name, first letter uppercase
const Product = bookshelf.model('Product',{
    'tableName':'products',
    category() {
        return this.belongsTo('Category') // first argument must be the name of a model
    },
    tags(){
        return this.belongsToMany('Tag')
    }
})

const Category = bookshelf.model('Category', {
    'tableName':'categories', // <-- the name of the table inside the MYSQL database
    products() {
        return this.hasMany('Product') // first argument must be the name of a model
    }
})

const Tag = bookshelf.model('Tag', {
    'tableName': 'tags', // <-- the tags table in the database
    products() {
        return this.belongsToMany('Product')  // first argument must be the name of a Model
    }
})

const User = bookshelf.model('User', {
    'tableName': 'users'
})

const CartItem = bookshelf.model('CartItem', {
    'tableName': 'cart_items',
    product() {
        return this.belongsTo('Product')
    },
    user() {
        return this.belongsTo('User')
    }

})

const BlacklistedToken = bookshelf.model('BlacklistedToken',{
    'tableName': 'blacklisted_tokens'
})

module.exports = { 
    'Product': Product,
    'Category': Category,
    'Tag': Tag,
    'User': User,
    'CartItem': CartItem,
    'BlacklistedToken': BlacklistedToken
}

// short form
// module.exports = {
//     Product
// }