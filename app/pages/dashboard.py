import dash
from dash import html, dcc, dash_table, Input, Output, State, callback
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
from components.navbar import create_navbar
from data.fetch_data import load_raw_network_traffic, load_processed_network_traffic, load_sample_prediction
from app.callbacks import dashboard_callbacks
from dash_iconify import DashIconify

colors = {
    'primary': '#1e3a8a',
    'secondary': '#64748b',
    'success': '#22c55e',
    'danger': '#ef4444',
    'warning': '#f59e0b',
    'info': '#0ea5e9',
    'light': '#f8fafc',
    'dark': '#334155',
    'white': '#ffffff',
    'background': '#f5f7fa',
}

# Create Network Controls Card
def create_network_controls():
    return dbc.Card([
        dbc.CardHeader(html.H5("Network Controls", className="fw-bold")),
        dbc.CardBody([
            dbc.Form([
                dbc.Row([
                    dbc.Label("Interface", width="5px"),
                    dbc.Col(
                        dbc.Input(
                            id="interface-input",
                            type="text",
                            placeholder="eth0",
                            # value="any",
                        ),
                        className="pe-2",
                    ),
                ], className="align-items-center"),
                
                dbc.Row([
                    dbc.Label("Time Range", width="2px"),
                    dbc.Col(
                        dbc.Input(
                            id="time-input",
                            type="text",
                            placeholder="30",
                        ),
                        className="pe-2",
                    ),
                ], className="mb-1 align-items-center"),
                
                dbc.Row([
                    dbc.Col(
                        dbc.Button(
                            "START", 
                            id="start-button", 
                            className="w-15"
                        ),
                        width=8,
                        className="d-flex justify-content-center mt-4"
                    ),
                ], justify="center"),
            ]),
        ]),
    ], className="shadow-sm", style={"margin-top": "0.5rem"})

# Create Packet Summary Card
def create_packet_summary():
    return dbc.Card([
        dbc.CardHeader(html.H5("Flow Summary", className="fw-bold")),
        dbc.CardBody([
            dbc.Row([
                dbc.Col(html.Div("Number Flow Captured:"), width=8),
                dbc.Col(html.Div(id="packet-count", children="0"), width=4, className="text-end fw-bold"),
            ], className="mb-2"),
            dbc.Row([
                dbc.Col(html.Div("Total Bytes:"), width=8),
                dbc.Col(html.Div(id="total-bytes", children="0 KB"), width=4, className="text-end fw-bold"),
            ], className="mb-2"),
            dbc.Row([
                dbc.Col(html.Div("Lost:"), width=8),
                dbc.Col(html.Div(id="lost-packets", children="0"), width=4, className="text-end fw-bold text-danger"),
            ], className="mb-2"),
            dbc.Row([
                dbc.Col(html.Div("Duration:"), width=8),
                dbc.Col(html.Div(id="duration", children="00:00:00"), width=4, className="text-end fw-bold"),
            ], className="mb-2"),
        ]),
    ], className="shadow-sm mt-3")

def create_detection_results():
    return dbc.Card([
        dbc.CardHeader(html.H5("Detection Results", className="fw-bold")),
        dbc.CardBody(
            id='detection-results',
            children="Vui lòng chọn một mẫu để xem kết quả phát hiện."
        ),
    ], className="shadow-sm mt-3")

# Create Initial Traffic Table
def create_initial_traffic_table():
    df = load_raw_network_traffic()

    if df.empty:
        df = pd.DataFrame(columns=[
            "Proto","AckDat","sHops","Seq", "State", "TcpRtt", 
            "dmeansz","offset","sttl", "flgs", "mean", "cause", 
            "stcpb", "dloss","smeansz","loss", "dttl", "sbytes", "bytes" 
        ])
    
    return dbc.Card([
        dbc.CardHeader(html.H5("Initial Traffic", className="fw-bold")),
        dbc.CardBody([
            dash_table.DataTable(
                id='initial-traffic-table',
                columns=[{"name": i, "id": i} for i in df.columns],
                data=df.to_dict('records'),
                style_table={'overflowX': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '8px',
                    'fontFamily': 'Arial, sans-serif',
                    'fontSize': '13px',
                },
                style_header={
                    'backgroundColor': colors['light'],
                    'fontWeight': 'bold',
                    'color': colors['secondary'],
                    'borderBottom': f'1px solid {colors["secondary"]}',
                },
                page_size=5,
            )
        ]),
    ], className="shadow-sm mt-4")
# Create Processed Traffic Table
def create_processed_traffic_table():
    df = load_processed_network_traffic()
    if df.empty:
        df = pd.DataFrame(columns=[
            'tcp', 'AckDat', 'sHops', 'Seq', 'RST', 'TcpRtt', 'REQ', 
            'dMeanPktSz','Offset', 'CON', 'FIN', 'sTtl', ' e        ', 
            'INT', 'Mean', 'Status', 'icmp', 'SrcTCPBase', ' e d      ', 
            'sMeanPktSz', 'DstLoss', 'Loss', 'dTtl', 'SrcBytes', 'TotBytes'
        ])
    
    return dbc.Card([
        dbc.CardHeader(html.H5("Processed Traffic",className="fw-bold")),
        dbc.CardBody([
            dash_table.DataTable(
                id='processed-traffic-table',
                columns=[{"name": i, "id": i} for i in df.columns],
                data=df.to_dict('records'),
                style_table={'overflowX': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '8px',
                    'fontFamily': 'Arial, sans-serif',
                    'fontSize': '13px',
                },
                style_header={
                    'backgroundColor': colors['light'],
                    'fontWeight': 'bold',
                    'color': colors['secondary'],
                    'borderBottom': f'1px solid {colors["secondary"]}',
                },
                page_size=5,
            )
        ]),
    ], className="shadow-sm", style={"margin-top": "1rem"})
def create_sample_prediction_table(): 
    df = load_sample_prediction()
    if df.empty:
        df = pd.DataFrame(columns=[
            'sample_index', 'time', 'label', 'attack_type', 'attack_tool'
        ])
    
    style_data_conditional = [
        {
            'if': {'filter_query': '{label} = "Malicious"'},
            'color': colors['danger'],
            'fontWeight': 'bold'
        }
    ]
    return dbc.Card([
        dbc.CardHeader(html.H5("Sample Prediction",className="fw-bold")),
        dbc.CardBody([
            dash_table.DataTable(
                id='sample-prediction-table',
                columns=[{"name": i, "id": i} for i in df.columns],
                data=df.to_dict('records'),
                style_table={'overflowX': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '7px',
                    'fontFamily': 'Arial, sans-serif',
                    'fontSize': '13px',
                },
                style_header={
                    'backgroundColor': colors['light'],
                    'fontWeight': 'bold',
                    'color': colors['secondary'],
                    'borderBottom': f'1px solid {colors["secondary"]}',
                },
                style_data_conditional=style_data_conditional,
                page_size=5,
            )
        ]),
    ], className="shadow-sm", style={"margin-top": "1rem"})
def copyright_info():
    return dbc.Card(
        dbc.CardBody([
            html.Div([
                html.Div([
                    html.Span("© MAY - 2025 ", className="me-1"),
                    html.Span("VIETHOANG / BACAN", className="fw-bold"),
                ], className="text-secondary small text-center"),
                
                html.Div([
                    html.A("UNIVERSITY OF INFORMATION TECHNOLOGY", href="#", className="mx-1 text-decoration-none text-muted small"),
                    html.Br(),
                    html.A("FACULTY OF COMPUTER NETWORK AND COMMUNICATION", href="#", className="mx-1 text-decoration-none text-muted small d-block d-md-inline"),
                ], className="text-center mt-2"),

                html.Div([
                    # html.A(DashIconify(icon="mdi:github", width=24), href="https://github.com/VietHoang30-23VH/5G_Project_Final", className="mx-2", target="_blank"),
                    html.A(DashIconify(icon="mdi:linkedin", width=24), href="https://www.linkedin.com/school/university-of-information-technology", className="mx-2", target="_blank"),
                    html.A(DashIconify(icon="mdi:facebook", width=24), href="https://www.facebook.com/UIT.Fanpage", className="mx-2", target="_blank"),
                    html.A(DashIconify(icon="mdi:web", width=24), href="https://www.uit.edu.vn/", className="mx-2", target="_blank"),
                ], className="text-center mt-3"),
            ])  
        ]),
        className="border border-secondary rounded bg-transparent mt-3"
    )
# Main layout function
def create_dashboard(username):
    return html.Div([
        # Navigation Bar
        html.Div([
            create_navbar(username)
        ], className="sticky-top shadow-sm"),
        
        # Main Content
        dbc.Container([
            # First Row - Network Controls and Network Flow
            dbc.Row([
                # Left Column - Network Controls
                dbc.Col([
                    create_network_controls(),
                    create_packet_summary(),
                    create_detection_results(),
                    copyright_info(),
                ], width=3, style={"margin-top": "1rem"}),
                
                # Right Column - Network Flow Chart
                dbc.Col([
                    create_initial_traffic_table(),
                    create_processed_traffic_table(),
                    create_sample_prediction_table(),
                ], width=9),
            ]),
        ], fluid=True, className="py-3 mt-5 bg-white"),
], style={"height": "100vh", "width": "100vw"})