package tn.enig.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import tn.enig.dao.IDepartement;
import tn.enig.dao.IMateriel;
import tn.enig.model.Materiel;

@Controller
public class AppController {

	@Autowired
	public IDepartement daoDep;
    @Autowired
	public IMateriel daoMat;

    public void setDaoDep(IDepartement d) {
    	 daoDep=d;
    }
    
    public void setDaoMat(IMateriel m) {
    	daoMat=m;
    }
    
    
    @RequestMapping(value="/listdepartement",method =RequestMethod.GET)

    public String f(Model m) {
    	 m.addAttribute("listdep", daoDep.findAll());
    	return "listdep";
    	
    }
    @RequestMapping(value="/",method =RequestMethod.GET)

    public String f7(Model m) {
    	 m.addAttribute("listdep", daoDep.findAll());
    	return "listdep";
    	
    }
    
    
    @RequestMapping(value="/listMat",method =RequestMethod.GET)

    public String f2(Model m,@RequestParam(value="iddep") int iddep) {
    	m.addAttribute("listmat",daoMat.getAllMatByDepId(iddep));
    	m.addAttribute("depchoisi",daoDep.findOne(iddep));
    	return "listmateriel";
    	
    }
    

    @RequestMapping(value="/addMat",method =RequestMethod.GET)
    public String f3(Model m) {
    	m.addAttribute("listdep",daoDep.findAll());
    	return "addmat";
    	
    }
    
    @RequestMapping(value="/addMateriel",method =RequestMethod.GET)

    public String f4(Model m,HttpServletRequest req) {
         Materiel mat=new Materiel();
         mat.setEtat(Boolean.parseBoolean(req.getParameter("etat")));
         mat.setNumSerie(Integer.parseInt(req.getParameter("serie")));
         mat.setQte(Integer.parseInt(req.getParameter("qte")));
         mat.setTitre(req.getParameter("titre"));
         mat.setType(req.getParameter("type"));
         mat.setDep(daoDep.findOne(Integer.parseInt(req.getParameter("dep"))));
    	 daoMat.save(mat);
    	 m.addAttribute("iddep",Integer.parseInt(req.getParameter("dep")));
         return "redirect:/listMat";
    	
    }
    
    
    @RequestMapping(value="/delete",method =RequestMethod.GET)
    public String f5(Model m,@RequestParam(value="idmat") int idmat) {
    	Materiel mat=daoMat.findOne(idmat);
    	m.addAttribute("iddep",mat.getDep().getId());
    	daoMat.delete(idmat);
    	return "redirect:/listMat";
    	
    }
}
