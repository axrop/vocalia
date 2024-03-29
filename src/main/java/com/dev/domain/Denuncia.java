package com.dev.domain;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@Entity
@Table(name="DENUNCIA")
public class Denuncia {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="ID_DENUNCIA")
	private Integer idDenuncia;
	
	@Column(name="FC_ALTA_DENUNCIA", nullable = false)
	private LocalDateTime fcAltaDenuncia;
	
	@ManyToOne
	@JoinColumn(name="ID_FISCALIA", nullable = true)
	private CatalogosValores fiscalia;

	@ManyToOne
	@JoinColumn(name="ID_DELITO", nullable = false)
	private CatalogosValores tipoDelito;
	
	@Column(name="FC_HECHOS", nullable = false)
	private LocalDate fcHechos;
	
	@ManyToOne
	@JoinColumn(name="ID_AUXILIAR", nullable = false)
	private CatalogosValores auxiliar;
	
	@Column(name="NM_DENUNCIA", nullable = false)
	private String nmDenuncia;
	
	@Column(name="FC_PLAZO", nullable = false)
	private LocalDateTime fcPlazo;
	
	@ManyToOne // (fetch= FetcType.LAZY)
	@JoinColumn(name="ID_ESTADO", nullable = false)
	private CatalogosValores estadoDenuncia;
	
	@ManyToOne
	@JoinColumn(name="ID_MESA_PARTE", nullable = true)
	private CatalogosValores mesaParte;
	
	@Column(name="DS_DESCRIPCION")
	private String dsDescripcion;


	private  String nmExpedientePreparatoria;

	private  String nmExpedienteInvPreliminar;

	@ManyToOne
	@JoinColumn(name="ID_USUARIO")
	private  Usuario usuario;


	
/**indica el tipo de documento de la denuncia**/
	@ManyToOne
	@JoinColumn(name="ID_TIPO_DOCUMENTO", nullable = false)
	private CatalogosValores tipoDocumento;

	
	/***fecha de ingreso de documento de la denuncia***/
	@Column(name="FC_INGRESO_DOCUMENTO", nullable = false)
	private LocalDate fcIngresoDocumento;
	

	
	/**numero del documento del que se ha ejecutado la denuncia**/
	@Column(name="NM_DOCUMENTO", nullable = false)
	private String nmDocumento;

	//@JsonBackReference
	//@JsonIgnoreProperties({"denuncia", "hibernateLazyInitalizer", "handler"})
	//@JsonIgnoreProperties({"denuncia", "lstDenunciantes"})
	@JsonBackReference
	@OneToMany(mappedBy = "denuncia", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
	private Set<DenunciaPersona> lstDenunciantes = new HashSet<>();


	//@JsonBackReference
	//@JsonIgnoreProperties({"denuncia", "hibernateLazyInitalizer", "handler"})
	//@JsonIgnoreProperties({"denuncia", "lstDenunciados"})
	@JsonBackReference
	@OneToMany(mappedBy = "denuncia", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
	private Set<DenunciaPersona> lstDenunciados = new HashSet<>();


	@Column(name="CD_USU_ALTA")
	private String cdUsuAlta;

	@Column(name="CD_USU_BAJA")
	private String cdUsuBaja;

	@Column(name="CD_USU_MODIF")
	private String cdUsuModif;

	@Column(name="FC_ALTA_FILA")
	private LocalDateTime fcAltaFila;

	@Column(name="FC_MODIF_FILA")
	private LocalDateTime fcModifFila;

	@Column(name="FC_BAJA_FILA")
	private LocalDateTime fcBajaFila;


}
