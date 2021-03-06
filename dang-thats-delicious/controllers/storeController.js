const mongoose = require('mongoose');
const Store = mongoose.model('Store');
const multer = require('multer');
const jimp = require('jimp');
const uuid = require('uuid');

const multerOptions = {
    storage: multer.memoryStorage(),
    fileFilter(req, file, next) {
        const isPhoto = file.mimetype.startsWith('image/');
        if (isPhoto) {
            next(null, true);
        } else {
            next({ message: 'That filetype isn\'t allowed' }, false);
        }
    }
}

exports.homePage = (req, res) => {
    console.log(req.name);
    res.render('index');
};
exports.addStore = (req, res) => {
    res.render('editStore', { title: 'Add Store' });
};
exports.upload = multer(multerOptions).single('photo');
exports.resize = async (req, res, next) => {
    // check if there is no new file to resize
    if (!req.file) {
        return next(); //skip to the next middleware
    }
    const extension = req.file.mimetype.split('/')[1];
    req.body.photo = `${uuid.v4()}.${extension}`;
    //now we resize
    const photo = await jimp.read(req.file.buffer);
    await photo.resize(800, jimp.AUTO);
    await photo.write(`./public/uploads/${req.body.photo}`);
    //once we have written the photo to out filesystem, keep going
    next();
}
exports.createStore = async (req, res) => {
    req.body.author = req.user._id;
    const store = await (new Store(req.body)).save();
    await store.save();
    req.flash('success', `Successfully Created ${store.name}. Care to leave a review?`);
    res.redirect(`/store/${store.slug}`);
};
exports.getStores = async (req, res) => {
    // 1. Query the database for a list of all stores
    const stores = await Store.find();
    res.render('stores', { title: 'Stores', stores });
};
const confirmOwner = (store, user) => {
    if (!store.author.equals(user._id)) {
        throw Error('You must own a store in order to edit it!');
    }
}
exports.editStore = async (req, res) => {
    // 1. Find the store given the id
    const store = await Store.findOne({ _id: req.params.id });
    // 2. Confirm they are the owner of the store
    confirmOwner(store, req.user);
    // 3. Render out the edit form so the user can update their store
    res.render('editStore', { title: `Edit ${store.name}`, store });
};
exports.updateStore = async (req, res) => {
    // Set location data to be a point
    req.body.location.type = 'Point';
    // 1. Find and update store
    const store = await Store.findOneAndUpdate({ _id: req.params.id }, req.body, {
        new: true,
        runValidators: true
    }).exec();
    req.flash('success', `Successfully updated <strong>${store.name}</strong>. <a href="/stores/${store.slug}">View Store</a>`);
    // 2. Redirect to store and tell them it worked
    res.redirect(`/stores/${store._id}/edit`);
};
exports.getStoreBySlug = async (req, res, next) => {
    const store = await Store.findOne({ slug: req.params.slug });
    if (!store) {
        return next();
    }
    res.render('store', { store, title: store.name });
};
exports.getStoresByTag = async (req, res) => {
    const tag = req.params.tag;
    const tagQuery = tag || { $exists: true };
    const tagsPromise = Store.getTagsList();
    const storesPromise = Store.find({ tags: tagQuery });
    // Instead of waiting for each one separately, call both at the same time and wait for the longest one
    const [tags, stores] = await Promise.all([tagsPromise, storesPromise]);
    res.render('tag', { tags, title: 'Tags', tag, stores });
};
exports.searchStores = async (req, res) => {
    // first find stores that match
    const stores = await Store
        .find({
            $text: { $search: req.query.q }
        }, {
            score: { $meta: 'textScore' }
        })
        // then sort them
        .sort({
            score: { $meta: 'textScore' }
        })
        // limit to only 5 results
        .limit(5);
    res.json(stores);
};