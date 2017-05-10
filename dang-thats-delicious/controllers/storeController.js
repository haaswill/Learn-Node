exports.homePage = (req, res) => {
    console.log(req.name);
    res.render('index');
};

exports.myMiddleware = (req, res, next) => {
    req.name = 'Will';
    next();
};