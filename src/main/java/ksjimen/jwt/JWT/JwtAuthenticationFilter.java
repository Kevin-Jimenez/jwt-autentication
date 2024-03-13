package ksjimen.jwt.JWT;

import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		/*Obtenemos el token*/
		final String token = getTokenFromRequest(request);
		final String username;
		
		if(token == null) {
			filterChain.doFilter(request, response);
			return;
		}
		username = jwtService.getUsernameFromToken(token);
		if(username != null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			if(jwtService.isTokenValid(token, userDetails)) {
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
						userDetails,
						null,
						userDetails.getAuthorities());
				
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		
		filterChain.doFilter(request, response);
		
	}
	
	/*Metodo para obtener el token que viene del request*/
	private String getTokenFromRequest(HttpServletRequest request) {
		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		/*Validar y extraer el token sin la palabra Berer*/
		if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
			return authHeader.substring(7);/*Si authHeader tiene el token, lo retorna despues de la palabra Bearer*/
		}
		return null;
	}

}