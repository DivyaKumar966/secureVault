import multer from "multer";

const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {

    const allowedTypes = [

        // Images
        "image/jpeg",
        "image/png",
        "image/jpg",
        "image/webp",

        // Videos
        "video/mp4",
        "video/quicktime",
        "video/x-msvideo",
        "video/x-matroska",

        // Documents
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",

        // Text
        "text/plain"
    ];

    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error("Unsupported File Type"), false);
    }
};

const upload = multer({

    storage,

    fileFilter,

    limits: {
        fileSize: 100 * 1024 * 1024
    }

});

export default upload;