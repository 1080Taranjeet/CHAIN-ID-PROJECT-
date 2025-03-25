import React from 'react';
import { Link } from "react-router-dom";
import "./Nav1.css";
import img from "../../Images/logo transparent.png";
import { useEffect, useState } from "react";
import ThemeToggle from '../../theme/ThemeToggle';
import { useTheme } from '../../theme/ThemeContext';
import { useTheme as useMUITheme } from '@mui/material/styles';

const Navbar = () => {

  const [url, seturl] = useState();

  const { toggleTheme, isDarkMode } = useTheme(); // Get the toggle function
  const theme = useMUITheme(); // Get the MUI theme

  useEffect(() => {
    const url = window.location.pathname;
    // console.log(url);
    seturl(url);
  }, [])

  useEffect(() => {

    // Find all elements with the class 'nav-link'
    const navLinkElements = document.querySelectorAll('.nav-link');

    // Set the color for each nav-link element based on the theme
    navLinkElements.forEach((element) => {
      element.style.color = theme.palette.text.primary; // Use the textColor state
    });

    const activeElements = document.querySelectorAll('.nav-active');

    // Set the border color for each nav-active element
    activeElements.forEach((element) => {
      element.style.borderColor = theme.palette.border.main; // Set border color based on the theme
    });

    const navLinkSubElements = document.querySelectorAll('.nav-link-sub');

    // Set the text and background color for each nav-link-sub element based on the theme
    navLinkSubElements.forEach((element) => {
      element.style.color = theme.palette.text.hover; // Text color
      element.style.backgroundColor = theme.palette.background.hover; // Background color
    });
  }, [theme]);

  return (
    <div className="" >
      <nav className="navbar fixed-top navbar-expand-lg d-xl-block d-none navbar-dark p-3 ">
        <div className="nav-main container-fluid d-flex align-items-center justify-content-between rounded"
          style={{
            backgroundColor: theme.palette.background.secondary,
          }}
        >
          <div className="sub-main d-flex align-items-center col-4" >
            <div className="col-2  text-center" >
              <img src={img} className="object-fit col-10 " />
            </div>
            <Link to={"/"} className="text-decoration-none main-heading h1"
              style={{
                color: theme.palette.primary.main,
              }}
            > CHAIN ID </Link>
          </div>
          <div className="sub-main text-white d-flex align-items-center justify-content-center col-4 " >
            <Link to="/"
              className={url === "/" ? "text-decoration-none nav-link nav-active" : "text-decoration-none nav-link"}
            >
              <p  >Home</p>
              <div className="nav-link-sub">Home</div>
            </Link>
            <Link to="/Contact"
              className={url === "/Contact" ? "text-decoration-none nav-link nav-active" : "text-decoration-none nav-link"}
            >
              <p  >Contact us</p>
              <div className="nav-link-sub">Contact us</div>
            </Link>
            <Link to="/Documentation"
              className={url === "/Documentation" ? "text-decoration-none nav-link nav-active" : "text-decoration-none nav-link"}
            >
              <p  >Documentation</p>
              <div className="nav-link-sub">Documentation</div>
            </Link>
          </div>
          {
            url !== "/" && (
              <div className="sub-main text-white d-flex align-items-center justify-content-end col-3 pe-3" >
                {/* <Link to="" className="text-decoration-none login-link" >SignIn</Link>
                              <div className="line mx-5"></div>
                              <Link to="" className="text-decoration-none login-link" >SignUp</Link> */}
                <Link to={"/"} className="Home-button-main" >
                  <div className="Home-button-sub" >
                    <div></div>
                    <div></div>
                  </div>
                  <button type="button" className="Home-button m-xl-2 m-1 px-xl-4 px-1" > <p className="mx-3 my-xl-2 my-1 " style={{ color: "greenyellow" }} >Hire Me</p> </button>
                </Link>
              </div>
            )
          }

          <ThemeToggle toggleTheme={toggleTheme} isDarkMode={isDarkMode} />

        </div>
      </nav>
      <nav className="navbar fixed-top navbar-expand-lg d-xl-none d-block navbar-dark p-3 " >
        <div className="nav-main container-fluid d-flex align-items-center justify-content-between rounded">
          <div className="sub-main d-flex align-items-center col-md-4 col-7" >
            <img src={img} className="object-fit col-md-2 col-4 " />
            <Link to="" className="text-decoration-none main-heading h3" >TaranjeetDEV</Link>
          </div>
          <div className="col-md-1 col-sm-2 col-3 row px-4" data-bs-toggle="offcanvas" data-bs-target="#offcanvasWithBackdrop" aria-controls="offcanvasRight" >
            <div className="col-12 border border-white my-1" ></div>
            <div className="col-12 border border-white my-1" ></div>
            <div className="col-12 border border-white my-1" ></div>
          </div>
        </div>
      </nav>

      <div className="offcanvas nav-main offcanvas-end" tabIndex="-1" id="offcanvasWithBackdrop" aria-labelledby="offcanvasRightLabel">
        <div className="offcanvas-header bg-dark " style={{ color: "orangered" }}>
          <img src={img} className="object-fit col-md-2 col-2 " />
          <Link id="offcanvasRightLabel" className="text-decoration-none main-heading h4" >TaranjeetDEV</Link>
          <button type="button" className=" btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
        </div>
        <div className="row px-4 py-3 my-auto ">
          <Link to={"/"} className="text-decoration-none fs-5 text-white w-100 bg-black my-2 pe-0 "
            style={{ overflow: "hidden", borderBottom: "1px solid orangered" }}
          >Home <div className="w-25 float-end h-100  " style={{
            transform: " skewX(-30deg)", transformOrigin: "bottom right", background: "orangered"
          }}  ></div> </Link>
          <Link to={"/Skill"} className="text-decoration-none fs-5 text-white w-100 bg-black my-2 pe-0 "
            style={{ overflow: "hidden", borderBottom: "1px solid orangered" }}
          >About <div className="w-25 float-end h-100  " style={{
            transform: " skewX(-30deg)", transformOrigin: "bottom right", background: "orangered"
          }}  ></div> </Link>
          <Link to={""} className="text-decoration-none fs-5 text-white w-100 bg-black my-2 pe-0 "
            style={{ overflow: "hidden", borderBottom: "1px solid orangered" }}
          >Projects <div className="w-25 float-end h-100  " style={{
            transform: " skewX(-30deg)", transformOrigin: "bottom right", background: "orangered"
          }}  ></div> </Link>
          <Link to={""} className="text-decoration-none fs-5 text-white w-100 bg-black my-2 pe-0 "
            style={{ overflow: "hidden", borderBottom: "1px solid orangered" }}
          >Resume <div className="w-25 float-end h-100  " style={{
            transform: " skewX(-30deg)", transformOrigin: "bottom right", background: "orangered"
          }}  ></div> </Link>
        </div>

        {
          url !== "/" && (
            <div className="sub-main text-white bg-dark d-flex align-items-center justify-content-center py-3 mt-auto " >
              {/* <Link to="" className="text-decoration-none text-white login-link" >SignIn</Link>
                          <div className="line mx-5"></div>
                          <Link to="" className="text-decoration-none text-white login-link" >SignUp</Link> */}
              <Link className="Home-button-main" >
                <div className="Home-button-sub" >
                  <div></div>
                  <div></div>
                </div>
                <button type="button" className="Home-button h5 m-xl-4 m-3 px-xl-5 px-3" > <p style={{ color: "greenyellow" }} className="mx-5 my-xl-3 my-2" >Hire Me</p> </button>
              </Link>
            </div>
          )
        }

      </div>
    </div>
  );
};

export default Navbar;