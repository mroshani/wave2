import React, { Component } from 'react';

class Header extends Component {
    render() {
        return (
            <header className="bck_b_light">
                <div className="container">
                    <div className="left">
                        <div className="logo">
                            SERKA
                        </div>
                    </div>
                    <div className="right">
                        <div className="top">
                            LINKS
                        </div>
                        <div className="bottom">
                            LINK
                        </div>
                    </div>
                </div>
            </header>
        );
    }
}

export default Header;