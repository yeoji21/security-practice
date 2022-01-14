package com.example.jwt.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        System.out.println("filter 1");
        req.setCharacterEncoding("UTF-8");

        // 원하는 토큰일때만 필터 체인을 탈 수 있도록
        // 이 토큰은 ID, PW가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
        // 그 후, 클라이언트가 요청할 때마다 header에 Authorization에 value값으로 토큰을 가져오면
        // 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨
        if (req.getMethod().equals("POST")) {
            System.out.println("CALL POST");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if(headerAuth.equals("cos"))
                chain.doFilter(req, res);
            else{
                PrintWriter out = res.getWriter();
                out.println("NOT ALLOW");
            }
        }
    }
}
