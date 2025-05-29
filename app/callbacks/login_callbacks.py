from dash import Output, Input, State, no_update, html
from dash import dcc
from data.database import users, engine
from app.pages.login import create_login_layout
from app.pages.dashboard import create_dashboard
from components.navbar import create_navbar
from app.pages.about import create_about_layout
import hashlib

def register_callbacks(app):
    # Callback đăng nhập
    @app.callback(
        [Output('session-store', 'data'),
         Output('message-area', 'children'),
         Output('url', 'pathname')],
        [Input('login-button', 'n_clicks')],
        [State('username', 'value'),
         State('password', 'value')]
    )
    def process_login(n_clicks, username, password):
        if n_clicks is None or n_clicks == 0:
            return no_update, no_update, no_update
        
        if not username or not password:
            return no_update, "Vui lòng nhập tên đăng nhập và mật khẩu!", no_update
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = engine.connect()
        result = conn.execute(
            users.select().where(
                (users.c.username == username) & 
                (users.c.password == hashed_password)
            )
        )
        user = result.fetchone()
        conn.close()
        
        if user:
            new_session_data = {'logged_in': True, 'username': username}
            return new_session_data, "Đăng nhập thành công.", "/dashboard"
        else:
            return no_update, "Tên đăng nhập hoặc mật khẩu không chính xác!", no_update

    # Toggle hiển thị mật khẩu
    @app.callback(
        Output("password", "type"),
        Input("passwordToggle", "n_clicks"),
        State("password", "type")
    )
    def toggle_password_visibility(n_clicks, current_type):
        if n_clicks is None:
            return "password"
        
        if current_type == "password":
            return "text"
        return "password"

    @app.callback(
        [Output('session-store', 'clear_data'),
        Output('url', 'pathname', allow_duplicate=True)],
        [Input('logout-button', 'n_clicks')],
        prevent_initial_call=True
    )
    def logout_user(n_clicks):
        if n_clicks:
            return True, "/"  # Xóa session data và chuyển hướng về trang login
        return no_update, no_update

    @app.callback(
        Output("page-content", "children"),
        [Input("url", "pathname")],
        [State("session-store", "data")]
    )
    def display_page(pathname, session_data):
        # Giá trị mặc định
        logged_in = False
        username = "User"
        
        # Cập nhật từ session_data nếu có
        if session_data:
            logged_in = session_data.get('logged_in', False)
            username = session_data.get('username', 'User')
        
        # In thông tin để debug
        print(f"Navigating to: {pathname}, Session data: {session_data}")
        
        # Kiểm tra trạng thái đăng nhập
        if logged_in:
            if pathname == '/about':
                return create_about_layout(username)
            elif pathname in ['/', '/dashboard']:
                return create_dashboard(username)
            elif pathname == '/logout':
                return [
                    create_login_layout(),
                    dcc.Location(id='logout-redirect', pathname='/', refresh=True)
                ]
            else:
                # Trang 404
                return html.Div([
                    html.H1("404 - Page Not Found", className="text-center mt-5"),
                    html.P(f"Path '{pathname}' không tìm thấy", className="text-center"),
                    dcc.Link("Quay lại Dashboard", href="/dashboard", className="btn btn-primary")
                ], className="container")
        else:
            # Nếu chưa đăng nhập, hiển thị trang login
            return create_login_layout()
        # Callback cập nhật thời gian
    @app.callback(
        Output("current-time", "children"),
        Input("interval-component", "n_intervals")
    )
    def update_datetime(n):
        from datetime import datetime
        now = datetime.now()
        day = f"{now.day:02d}"
        month = f"{now.month:02d}"
        year = now.year
        hours = f"{now.hour:02d}"
        minutes = f"{now.minute:02d}"
        seconds = f"{now.second:02d}"
        datetime_str = f"{day}/{month}/{year} - {hours}:{minutes}:{seconds}"
        return datetime_str