import "./HOMES.css";
// import vid from "../../files/light.mov.crdownload";
import img from "../../Images/faceID remove.png";
import { useEffect } from "react";
import { useTheme as useMUITheme } from '@mui/material/styles';
import { Link } from "react-router-dom";
import BackgroundVideo from "../../theme/BackgroundVideo";

export default function HOMES() {

  const theme = useMUITheme(); // Get the MUI theme

  useEffect(() => {
    const animation = (v) => {
      const value = document.getElementsByClassName("org-sub");
      if (value.length === 0) return; // Ensure elements exist
      if (v >= value.length) v = 0; // Stop if v exceeds the number of elements

      // Reset all elements to d-none
      Array.from(value).forEach((el) => {
        el.className = "org-sub d-none";
      });

      // Show the current element
      value[v].className = "org-sub d-block";

      // Move to the next element after 10 seconds
      setTimeout(() => {
        animation(v + 1); // Move to the next element
      }, 10000);
    };

    animation(0); // Start the animation

    // Cleanup function to reset the classes on unmount
    return () => {
      const value = document.getElementsByClassName("org-sub");
      Array.from(value).forEach((el) => {
        el.className = "org-sub d-none";
      });
    };
  }, []);

  useEffect(() => {
    document.getElementsByClassName("video")[0].style.rotate = "-180deg";
  }, [])
  return (
    <div className="scroll" id="main" >
      <div className="container-fluid p-0 m-0 d-flex scroll" >
        <BackgroundVideo />
        <div className="main row col-12 bg-transparent pt-md-0 pb-xl-5 pb-0 pt-5 mt-auto" id="Home">
          <div className="main-info ps-md-5 ps-sm-3 ps-3 d-flex align-items-center col-xxl-6 col-xl-6 col-lg-7 col-md-12 col-sm-12 col-12">

            <div className="text-light col-12 my-xl-0 my-5 mx-sm-0 mx-3 " >
              <p className=" m-0 " style={{ fontSize: "200%", color: theme.palette.text.primary }} >Welcome To,</p>
              <div className=" org d-flex" >
                <div className="org-sub d-none" >CHAIN ID </div>
                <div className="org-sub d-none ">Biomatric Authenticator</div>
                <div style={{ background: theme.palette.text.primary }}></div>
              </div>
              <div className=" fs-5 d-flex align-itmes-center pt-3 pb-5 pe-md-5 pe-3" >
                <p className="m-2 font " style={{ fontSize: "80%", color: theme.palette.text.primary }} >Driven web developer skilled in the MERN stack, creating cutting-edge, high-performance applications. Focused on delivering tailored solutions that boost business growth and elevate user experience.</p>
              </div>
              <div className="Home-button-main" style={{ transformOrigin: "top left" }} >
                <div className="Home-button-sub" >
                  <div></div>
                  <div></div>
                </div>
                <Link to={"/Signup"}>
                  <button type="button" className="Home-button h5 m-xl-4 m-3 px-xl-5 px-3" > <p className="mx-5 my-xl-3 my-2" style={{ color: theme.palette.text.primary }} >Get Started</p> </button>
                </Link>
              </div>
            </div>

          </div>

          <div className="main-img col-xxl-5 col-xl-5 col-lg-5 col-md-6 col-sm-6 col-6 d-flex justify-content-center align-items-center pt-5 ms-xl-auto me-xl-0 m-auto">
            <img src={img} alt="/" className="main-img-i" style={{ maxWidth: '100%', height: 'auto' }} />
          </div>
        </div>
      </div>
    </div>
  )
}