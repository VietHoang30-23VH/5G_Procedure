from dash import html, dcc
from dash_iconify import DashIconify

def create_login_layout():
    return html.Div(
        className='container', 
        children=[
            html.Div(
                className='login-box', 
                children=[
                    html.Div(
                        className='login-header', 
                        children=[
                            html.Div(
                                className='logo',
                                children=[
                                    DashIconify(
                                        icon="mdi:server", 
                                        width=90,
                                        height=60,
                                        color="currentColor"
                                    )
                                ]
                            ),
                            html.H2('Network Monitoring Dashboard')
                        ]
                    ),
                    html.Div(
                        className='login-form',
                        id='loginForm',
                        children=[
                            html.Div(
                                className='form-group',
                                children=[
                                    html.Label('Tên đăng nhập', htmlFor='username'),
                                    dcc.Input(
                                        type='text',
                                        id='username',
                                        className='form-control',
                                        placeholder='Nhập tên đăng nhập',
                                        required=True,
                                        value=''
                                    )
                                ]
                            ),
                            html.Div(
                                className='form-group',
                                children=[
                                    html.Label('Mật khẩu', htmlFor='password'),
                                    html.Div(
                                        style={'position': 'relative'},
                                        children=[
                                            dcc.Input(
                                                type='password',
                                                id='password',
                                                className='form-control',
                                                placeholder='Nhập mật khẩu',
                                                required=True,
                                                value='',
                                            ),
                                            html.Span(
                                                className='password-toggle',
                                                id='passwordToggle',
                                                children=[
                                                    html.I(
                                                        className='fas fa-eye',
                                                        style={
                                                            'position': 'absolute',
                                                            'right': '10px',
                                                            'top': '50%',
                                                            'transform': 'translateY(-50%)',
                                                            'cursor': 'pointer'
                                                        }
                                                    )
                                                ]
                                            )
                                        ]
                                    )
                                ]
                            ),
                            html.Button(
                                'Đăng nhập',
                                type='button',
                                className='btn',
                                id='login-button',
                                n_clicks=0
                            ),
                            html.Div(
                                id="message-area",
                                style={"marginTop": "10px"},
                            ),
                            html.Div(
                                className='server-status',
                                children=[
                                    html.Span(className='status-indicator'),
                                    " Trạng thái: ", 
                                    html.Strong("Đang hoạt động"),
                                    html.Div(id="current-time", className='datetime')
                                ]
                            )
                        ]
                    )
                ]
            ),
            dcc.Interval(
                id='interval-component',
                interval=1*1000,  
            ),
            dcc.Store(id='user-session', storage_type='session')
        ]
    )