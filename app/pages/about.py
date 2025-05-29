from dash import html
import dash_bootstrap_components as dbc
from components.navbar import create_navbar

def create_about_layout(username):
    return html.Div([
        create_navbar(username),
        dbc.Container([
            # Sử dụng d-flex và align-items-stretch để đảm bảo các cột có cùng chiều cao
            dbc.Row([
                # Cột trái
                dbc.Col([
                    # --- Giới thiệu ---
                    dbc.Card([
                        dbc.CardBody([
                            html.Strong("1. Introduction", className="mb-3 d-block"),
                            html.P(
                                "5G Network Monitor is a comprehensive 5G network monitoring and analysis system, designed to provide an overview of the performance, security, and operations of the 5G network system.",
                                style={"textAlign": "justify"}
                            ),
                            html.P(
                                "The system enables network administrators to monitor key metrics in real-time, detect and alert on security threats, as well as analyze network usage trends.",
                                style={"textAlign": "justify"}
                            )
                        ])
                    ], className="shadow-sm mb-4", style={"height": "200px"}),

                    # --- Tính năng chính ---
                    dbc.Card([
                        dbc.CardBody([
                            html.Strong("3. Main Features", className="mb-3 d-block"),
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        html.I(className="fas fa-chart-line fa-2x text-success mb-2"),
                                        html.H6("Real-time Monitoring", className="text-primary fw-bold"),
                                        html.P("Continuously monitor network traffic, performance, and other critical metrics in real-time.", 
                                              className="small",)
                                    ], className="text-center")
                                ], width=4),

                                dbc.Col([
                                    html.Div([
                                        html.I(className="fas fa-shield-alt fa-2x text-warning mb-2"),
                                        html.H6("Security Alerts", className="text-primary fw-bold"),
                                        html.P("Detect and provide early warnings of security threats and abnormal activities.",
                                              className="small",)
                                    ], className="text-center")
                                ], width=4),

                                dbc.Col([
                                    html.Div([
                                        html.I(className="fas fa-chart-area fa-2x text-info mb-2"),
                                        html.H6("Data Analysis", className="text-primary fw-bold"),
                                        html.P("Analyze trends, generate reports, and provide insights to optimize the network.",
                                              className="small",)
                                    ], className="text-center")
                                ], width=4),
                            ])
                        ])
                    ], className="shadow-sm", style={"height": "200px"})
                ], width=6),
                
                # Cột phải
                dbc.Col([
                    # --- Thông tin kỹ thuật ---
                    dbc.Card([
                        dbc.CardBody([
                            html.Strong("2. Technologies Used", className="mb-3 d-block"),
                            dbc.Row([
                                dbc.Col([
                                    html.I(className="fas fa-cloud-meatball fa-2x text-info mb-1 mt-3"),
                                    html.H6("5G Network", className="text-secondary"),
                                    html.P([
                                        html.A("free5GC", 
                                               href="https://free5gc.org/", 
                                               target="_blank",
                                               className="fw-bold text-decoration-none text-primary",
                                               style={"color": "inherit"})
                                    ])
                                ], width=3, className="text-center"),
                                dbc.Col([
                                    html.I(className="fas fa-laptop-code fa-2x text-info mb-1 mt-3"),
                                    html.H6("Network Tool", className="text-secondary"),
                                    html.P([
                                        html.A("Argus Tool", 
                                               href="https://openargus.org/", 
                                               target="_blank",
                                               className="fw-bold text-decoration-none text-primary",
                                               style={"color": "inherit"})
                                    ])
                                ], width=3, className="text-center"),
                                dbc.Col([
                                    html.I(className="fas fa-database fa-2x text-info mb-1 mt-3"),
                                    html.H6("Model", className="text-secondary"),
                                    html.P([
                                        html.A("Random Forest", 
                                               href="https://scikit-learn.org/stable/modules/ensemble.html#random-forests", 
                                               target="_blank",
                                               className="fw-bold text-decoration-none text-primary",
                                               style={"color": "inherit"})
                                    ])
                                ], width=3, className="text-center"),
                                dbc.Col([
                                    html.I(className="fas fa-sync fa-2x text-info mb-1 mt-3"),
                                    html.H6("Framework", className="text-secondary"),
                                    html.P([
                                        html.A("Python", 
                                               href="https://www.python.org/", 
                                               target="_blank",
                                               className="fw-bold text-decoration-none me-1 text-primary",
                                               style={"color": "inherit"}),
                                        ", ",
                                        html.A("Dash", 
                                               href="https://dash.plotly.com/", 
                                               target="_blank",
                                               className="fw-bold text-decoration-none me-1 text-primary",
                                               style={"color": "inherit"}),
                                        ", ",
                                        html.A("Plotly", 
                                               href="https://plotly.com/", 
                                               target="_blank",
                                               className="fw-bold text-decoration-none text-primary",
                                               style={"color": "inherit"})
                                    ])
                                ], width=3, className="text-center"),
                            ]), 
                        ])
                    ], className="shadow-sm mb-4", style={"height": "200px"}),

                    # --- Liên hệ hỗ trợ ---
                    dbc.Card([
                        dbc.CardBody([
                            html.Strong("4. Contact", className="mb-3 d-block"),
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        html.I(className="fas fa-envelope fa-2x text-primary mb-2"),
                                        html.H6("Email", className="fw-bold text-primary"),
                                        html.P([
                                            html.A("22520471@gm.uit.edu.vn", 
                                                   href="mailto:22520471@gm.uit.edu.vn", 
                                                   className="small mb-1 d-block text-decoration-none",
                                                   style={"color": "inherit"}),
                                            html.A("22520143@gm.uit.edu.vn", 
                                                   href="mailto:22520143@gm.uit.edu.vn", 
                                                   className="small text-decoration-none",
                                                   style={"color": "inherit"})
                                        ]),
                                    ], className="text-center")
                                ], width=4),

                                dbc.Col([
                                    html.Div([
                                        html.I(className="fas fa-phone fa-2x text-primary mb-2"),
                                        html.H6("Phone Number", className="fw-bold text-primary"),
                                        html.P([
                                            html.A("098 730 8446", 
                                                   className="small mb-1 d-block text-decoration-none",
                                                   style={"color": "inherit"}),
                                            html.A("035 279 9826",  
                                                   className="small text-decoration-none",
                                                   style={"color": "inherit"})
                                        ])
                                    ], className="text-center")
                                ], width=4),
                               dbc.Col([
                                    html.Div([
                                        html.I(className="fab fa-github fa-2x text-dark mb-2"),
                                        html.H6("Repository", className="fw-bold text-primary"),
                                        html.A(
                                            "https://github.com/VietHoang30-23VH/5G_Project_Final",
                                            href="https://github.com/VietHoang30-23VH/5G_Project_Final",
                                            target="_blank",
                                            className="small text-decoration-none",
                                            style={"color": "black"}  # <-- đặt trong đây
                                        ),
                                    ], className="text-center")
                                ], width=4),
                            ])
                        ])
                    ], className="shadow-sm", style={"height": "200px"})
                ], width=6)
            ], className="g-4 mt-5"),

            # --- Nút quay về Dashboard ---
            dbc.Row([
                dbc.Col([
                    html.Div([
                        dbc.Button(
                            [html.I(className="fas fa-arrow-left me-2"), "Quay về Dashboard"],
                            href="/dashboard",
                            color="primary",
                            size="lg",
                            className="shadow"
                        )
                    ], className="text-center")
                ], width=5)
            ], className="mt-5 mb-3 justify-content-center")

        ], fluid=True, className="py-3 mt-5 bg-white"),
    ], style={"height": "100%", "width": "100vw"})