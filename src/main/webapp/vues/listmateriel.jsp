<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
    <%@ taglib prefix="c"      uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.1/css/all.min.css" integrity="sha512-MV7K8+y+gLIBoVD59lQIYicR65iaqukzvf/nwasF0nqhPay5w/9lJmVM2hMDcnK1OnMGCdVK+iQrJ7lzPJQd1w==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
<meta charset="UTF-8">
<title>${depchoisi.titre }</title>
</head>

<body>
 
 <sec:authorize access="isAuthenticated()">
<a class="btn btn-danger" href="<c:url value="/logout" />">Logout</a> 
</sec:authorize>
  <div class="container">
 
  <h1 class="text-success">Liste des Materiels</h1>
   <h2>Département choisi : ${depchoisi.titre}</h2><br/>
   <h3><a href="addMat" class="btn btn-info"><i class="fa fa-plus"></i> ajouter un matierel</a></h3>
    <table class="table">
  <thead>
    <tr>
      <th scope="col">#</th>
      <th scope="col">Titre</th>
      <th scope="col">Serie</th>
      <th scope="col">Quantite</th>
      <th scope="col">Etat</th>
      <th scope="col">Supprimer</th>
    </tr>
  </thead>
  <tbody>
     <c:forEach var="m" items="${listmat}">
          <tr>
      <th scope="row">${m.id}</th>
      <td>${m.titre}</td>
      <td>${m.numSerie}</td>
      <td>${m.qte}</td>
      <td><c:out value="${m.etat eq true ? 'fonctionnel' : 'défectueux' }" ></c:out></td>
      <td><a href="delete?idmat=${m.id}"><i class="fa fa-trash"></i></a></td>       
    </tr>
     </c:forEach>
  
  </tbody>
</table>
  </div>
</body>
</html>