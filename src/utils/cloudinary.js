import { v2 as cloudinary } from "cloudinary";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) return null;

    //uploading file on cloudindary successfully
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    console.log("file has uploaded successfully", response.url);

    return response;
  } catch (error) {
    fs.unlinkSync(localFilePath);
    //remove the locally saved temporary file as the upload operartion got failed
    return null;
  }
};

export { uploadOnCloudinary };